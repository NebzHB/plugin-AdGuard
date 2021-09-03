<?php

/* This file is part of Jeedom.
*
* Jeedom is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Jeedom is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Jeedom. If not, see <http://www.gnu.org/licenses/>.
*/

/* * ***************************Includes**********************************/
require_once dirname(__FILE__) . '/../../../../core/php/core.inc.php';

class AdGuard extends eqLogic {
	/***************************Attributs*******************************/	
	public static function cron($_eqlogic_id = null) {
		$eqLogics = ($_eqlogic_id !== null) ? array(eqLogic::byId($_eqlogic_id)) : eqLogic::byType('AdGuard', true);
		foreach ($eqLogics as $AdGuard) {
			$autorefresh = $AdGuard->getConfiguration('autorefresh','*/5 * * * *');
			if ($autorefresh != '') {
				try {
					$c = new Cron\CronExpression(checkAndFixCron($autorefresh), new Cron\FieldFactory);
					if ($c->isDue()) {
						$AdGuard->getAdGuardInfo();
					}
				} catch (Exception $exc) {
					log::add('AdGuard', 'error', __('Expression cron non valide pour ', __FILE__) . $AdGuard->getHumanName() . ' : ' . $autorefresh);
				}
			}
		}
	}	
	
	public static function getStructure ($name) {
	
		switch($name) {
			case "status" :
				return ["num_dns_queries"=>"Requêtes DNS",
						"num_blocked_filtering"=>"Bloqué par Filtres",
						"num_replaced_safebrowsing"=>"Tentative de malware/hameçonnage bloquée",
						"num_replaced_safesearch"=>"Recherche sécurisée forcée",
						"num_replaced_parental"=>"Sites à contenu adulte bloqués",
						"avg_processing_time"=>"Temps moyen de traitement"
					];
			break;
		}		
	}
	
	public function postAdGuard($cmd,$params) {
		$ip = $this->getConfiguration('ip','');
		
		$url = 'http://' . $ip . '/control/'.$cmd;
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');
		
		$request_http = new com_http($url,$user,$pass);
		$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		$request_http->setHeader(array(
			'Content-Type: application/json',
//			'Authorization: Basic '.base64_encode($user.':'.$pass),
			'Accept application/json, text/plain, */*'
		));
		$request_http->setPost(json_encode($params));
				
		$AdGuardinfo=$request_http->exec(10,1);
		
		return json_decode($AdGuardinfo,true);
	}
	
	public function getAdGuard($cmd,$params=null) {
		$ip = $this->getConfiguration('ip','');
		
		$url = 'http://' . $ip . '/control/'.$cmd;
		$url.=((count($params))?"?".http_build_query($params):'');
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');
		
		$request_http = new com_http($url,$user,$pass);
		$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		$request_http->setHeader(array(
			'Content-Type: application/json',
//			'Authorization: Basic '.base64_encode($user.':'.$pass),
			'Accept application/json, text/plain, */*'
		));
		
				
		$AdGuardinfo=$request_http->exec(10,1);
		
		return json_decode($AdGuardinfo,true);
	}
	
	public function getAdGuardInfo() {
		try {
				
			$AdGuardinfo=$this->getAdGuard('status');
			$AdGuardinfo['safebrowsing']=$this->getAdGuard('safebrowsing/status');
			$AdGuardinfo['parental']=$this->getAdGuard('parental/status');
			$AdGuardinfo['safesearch']=$this->getAdGuard('safesearch/status');
			$AdGuardinfo['filtering']=$this->getAdGuard('filtering/status');
			$AdGuardinfo['filtering']['filters']="deleted";
			$AdGuardinfo['stats']=$this->getAdGuard('stats');
			$AdGuardinfo['stats']['top_queried_domains']="deleted";
			$AdGuardinfo['stats']['top_clients']="deleted";
			$AdGuardinfo['stats']['top_blocked_domains']="deleted";
			$AdGuardinfo['stats']['dns_queries']="deleted";
			$AdGuardinfo['stats']['blocked_filtering']="deleted";
			$AdGuardinfo['stats']['replaced_safebrowsing']="deleted";
			$AdGuardinfo['stats']['replaced_parental']="deleted";
			$AdGuardinfo['version']=$this->getAdGuard('version.json');
			$AdGuardinfo+=$this->getAdGuard('clients');
			$AdGuardinfo['auto_clients']="deleted";
			$AdGuardinfo['supported_tags']="deleted";


			log::add('AdGuard','debug','recu:'.json_encode($AdGuardinfo));
			return
			
			$AdGuardCmd = $this->getCmd(null, 'protection_enabled');
			$this->checkAndUpdateCmd($AdGuardCmd, (($AdGuardinfo['protection_enabled']===true)?1:0));
			
			$status = AdGuard::getStructure('status');
			foreach($summaryRaw as $id => $trad) {
				$AdGuardCmd = $this->getCmd(null, $id);
				if(strpos($id,'avg_processing_time') !== false) $AdGuardinfo['stats'][$id]=round($AdGuardinfo['stats'][$id],0);
				$this->checkAndUpdateCmd($AdGuardCmd, $AdGuardinfo['stats'][$id]);
			}
			
			$AdGuardCmd = $this->getCmd(null, 'hasUpdateAdGuard');
			$this->checkAndUpdateCmd($AdGuardCmd, (($AdGuardinfo['version']['can_autoupdate']===true)?1:0));

			
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '1');
			}
		} catch (Exception $e) {
			if($e->getCode() == "404") {
				$online = $this->getCmd(null, 'online');
				if (is_object($online)) {
					$this->checkAndUpdateCmd($online, '0');
				}
			}
		}
	} 
	
	public function getImage(){
		return 'plugins/AdGuard/plugin_info/AdGuard_icon.png';
	}
	
	public function postSave() {
		$order=1;
		$protection_enabled = $this->getCmd(null, 'protection_enabled');
		if (!is_object($protection_enabled)) {
			$protection_enabled = new AdGuardcmd();
			$protection_enabled->setLogicalId('protection_enabled');
			$protection_enabled->setIsVisible(1);
			$protection_enabled->setOrder($order);
			$protection_enabled->setName(__('Statut', __FILE__));
		}
		$protection_enabled->setType('info');
		$protection_enabled->setSubType('binary');
		$protection_enabled->setEqLogic_id($this->getId());
		$protection_enabled->setDisplay('generic_type', 'SWITCH_STATE');
		$protection_enabled->save();
		
		$order++;
		$protection_enable = $this->getCmd(null, 'protection_enable');
		if (!is_object($protection_enable)) {
			$protection_enable = new AdGuardcmd();
			$protection_enable->setLogicalId('protection_enable');
			$protection_enable->setDisplay('icon','<i class="fas fa-play"></i>');
			$protection_enable->setIsVisible(1);
			$protection_enable->setOrder($order);
			$protection_enable->setName(__('Activer le filtrage', __FILE__));
		}
		$protection_enable->setType('action');
		$protection_enable->setSubType('other');
		$protection_enable->setEqLogic_id($this->getId());
		$protection_enable->setValue($protection_enabled->getId());
		$protection_enable->setDisplay('generic_type', 'SWITCH_ON');
		$protection_enable->save();
		
		$order++;
		$protection_disable = $this->getCmd(null, 'protection_disable');
		if (!is_object($protection_disable)) {
			$protection_disable = new AdGuardcmd();
			$protection_disable->setLogicalId('protection_disable');
			$protection_disable->setDisplay('icon','<i class="fas fa-stop"></i>');
			$protection_disable->setIsVisible(1);
			$protection_disable->setOrder($order);
			$protection_disable->setName(__('Désactiver le filtrage', __FILE__));
		}
		$protection_disable->setType('action');
		$protection_disable->setSubType('other');
		$protection_disable->setEqLogic_id($this->getId());
		$protection_disable->setValue($protection_enabled->getId());
		$protection_disable->setDisplay('generic_type', 'SWITCH_OFF');
		$protection_disable->save();
		
		$order++;
		$refresh = $this->getCmd(null, 'refresh');
		if (!is_object($refresh)) {
			$refresh = new AdGuardcmd();
			$refresh->setLogicalId('refresh');
			$refresh->setIsVisible(1);
			$refresh->setOrder($order);
			$refresh->setName(__('Rafraîchir', __FILE__));
		}
		$refresh->setType('action');
		$refresh->setSubType('other');
		$refresh->setEqLogic_id($this->getId());
		$refresh->save();

		$status = AdGuard::getStructure('status');
		
		foreach($status as $id => $trad) {
			$order++;
			$newCommand = $this->getCmd(null, $id);
			if (!is_object($newCommand)) {
				$newCommand = new AdGuardcmd();
				$newCommand->setLogicalId($id);
				$newCommand->setIsVisible(0);
				$newCommand->setOrder($order);
				$newCommand->setName(__($trad, __FILE__));
			}
			$newCommand->setTemplate('dashboard', 'line');
			$newCommand->setTemplate('mobile', 'line');
			$newCommand->setType('info');
			$newCommand->setSubType('numeric');
			$newCommand->setEqLogic_id($this->getId());
			$newCommand->setDisplay('generic_type', 'GENERIC_INFO');
			if(strpos($id,'avg_processing_time') !== false) $newCommand->setUnite( 'ms' );
			$newCommand->save();		
		}
		
		$order++;
		$online = $this->getCmd(null, 'online');
		if (!is_object($online)) {
			$online = new AdGuardcmd();
			$online->setLogicalId('online');
			$online->setIsVisible(1);
			$online->setOrder($order);
			$online->setName(__('Online', __FILE__));
		}
		$online->setType('info');
		$online->setSubType('binary');
		$online->setEqLogic_id($this->getId());
		$online->setDisplay('generic_type', 'ONLINE');
		$online->save();	

		$order++;
		$hasUpdateAdGuard = $this->getCmd(null, 'hasUpdateAdGuard');
		if (!is_object($hasUpdateAdGuard)) {
			$hasUpdateAdGuard = new AdGuardcmd();
			$hasUpdateAdGuard->setLogicalId('hasUpdateAdGuard');
			$hasUpdateAdGuard->setIsVisible(1);
			$hasUpdateAdGuard->setOrder($order);
			$hasUpdateAdGuard->setName(__('Update AdGuard Dispo', __FILE__));
		}
		$hasUpdateAdGuard->setType('info');
		$hasUpdateAdGuard->setSubType('binary');
		$hasUpdateAdGuard->setEqLogic_id($this->getId());
		$hasUpdateAdGuard->save();
		
		$order++;
		$this->getAdGuardInfo();
	}
}

class AdGuardCmd extends cmd {
	/***************************Attributs*******************************/


	/*************************Methode static****************************/

	/***********************Methode d'instance**************************/
  	public function refresh() {
		$this->execute();
	    }
	
	public function execute($_options = null) {
		if ($this->getType() == '') {
			return '';
		}
		$eqLogic = $this->getEqlogic();
		$ip = $eqLogic->getConfiguration('ip','');
		$apikey = $eqLogic->getConfiguration('apikey','');
		$logical = $this->getLogicalId();
		$result=null;
		if ($logical != 'refresh'){

			switch ($logical) {
				case 'disable':
					$urlAdGuard = 'http://' . $ip . '/admin/api.php?disable&auth='.$apikey;
				break;
				case 'enable':
					$urlAdGuard = 'http://' . $ip . '/admin/api.php?enable&auth='.$apikey;
				break;
			}
			try{
				$request_http = new com_http($urlAdGuard);
				$result=$request_http->exec(60,1);
				$online = $eqLogic->getCmd(null, 'online');
				if (is_object($online)) {
					$eqLogic->checkAndUpdateCmd($online, '1');
				}
			}
			catch(Exception $e) {
				if($e->getCode() == "404") {
					$online = $eqLogic->getCmd(null, 'online');
					if (is_object($online)) {
						$eqLogic->checkAndUpdateCmd($online, '0');
					}
				}
				log::add('AdGuard','debug','AdGuard non joignable : '.$e->getCode());
			}
		}
		$eqLogic->getAdGuardInfo();
	}

	/************************Getteur Setteur****************************/
}
?>
