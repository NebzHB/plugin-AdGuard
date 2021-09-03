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
			case "summaryRaw" :
				return ["domains_being_blocked"=>"Domaines bloqués",
						"dns_queries_today"=>"Requêtes aujourd'hui",
						"ads_blocked_today"=>"Publicités bloquées aujourd'hui",
						"ads_percentage_today"=>"Pourcentage publicités bloquées aujourd'hui",
						"unique_domains"=>"Domaines uniques",
						"queries_forwarded"=>"Requêtes transmises",
						"queries_cached"=>"Requêtes en cache",
						"clients_ever_seen"=>"Clients vus",
						"unique_clients"=>"Clients uniques"
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
	
	public function getAdGuardInfo($data=null,$order=null) {
		try {
				
			if(!$data) {
				$AdGuardinfo=$this->getAdGuard('status');
			} else {
				$AdGuardinfo=$data;
			}

			log::add('AdGuard','debug','recu:'.$AdGuardinfo);
			
			return
			$jsonAdGuard = json_decode($AdGuardinfo,true);

			$AdGuardCmd = $this->getCmd(null, 'status');
			$this->checkAndUpdateCmd($AdGuardCmd, (($jsonAdGuard['status']=='enabled')?1:0));
			
			if($data) {
				$urlprinter = 'http://' . $ip . '/admin/api.php?summaryRaw&auth='.$apikey;
				$request_http = new com_http($urlprinter);
				$AdGuardinfo=$request_http->exec(60,1);
				log::add('AdGuard','debug','recu:'.$AdGuardinfo);
				$jsonAdGuard = json_decode($AdGuardinfo,true);
			}
			
			$summaryRaw = AdGuard::getStructure('summaryRaw');
			foreach($summaryRaw as $id => $trad) {
				$AdGuardCmd = $this->getCmd(null, $id);
				if(strpos($id,'percentage') !== false) $jsonAdGuard[$id]=round($jsonAdGuard[$id],2);
				$this->checkAndUpdateCmd($AdGuardCmd, $jsonAdGuard[$id]);
			}
			
			if(isset($jsonAdGuard['gravity_last_updated'])) { //v4
				$nextOrder = $order || 29;
				$gravity_last_updated = $this->getCmd(null, 'gravity_last_updated');
				if (!is_object($gravity_last_updated)) { // create if not exists
					$nextOrder++;
					$gravity_last_updated = new AdGuardcmd();
					$gravity_last_updated->setLogicalId('gravity_last_updated');
					$gravity_last_updated->setIsVisible(0);
					$gravity_last_updated->setOrder($nextOrder);
					$gravity_last_updated->setName(__('Dernière mise à jour', __FILE__));
				}
				$gravity_last_updated->setType('info');
				$gravity_last_updated->setSubType('string');
				$gravity_last_updated->setEqLogic_id($this->getId());
				$gravity_last_updated->setDisplay('generic_type', 'GENERIC_INFO');
				$gravity_last_updated->save();
				
				$time=$jsonAdGuard['gravity_last_updated']['absolute'];
				$date= new DateTime("@$time");
				$absolute = $date->format('d-m-Y H:i:s');
				
				$this->checkAndUpdateCmd($gravity_last_updated, $absolute);
			}
			
			$urlprinter = 'http://' . $ip . '/admin/api.php?versions';
			$request_http = new com_http($urlprinter);
			$AdGuardVer=$request_http->exec(60,1);
			log::add('AdGuard','debug','recu versions:'.$AdGuardVer);
			if($AdGuardVer) {
				$jsonAdGuardVer = json_decode($AdGuardVer,true);
				$AdGuardCmd = $this->getCmd(null, 'hasUpdateAdGuard');
				$this->checkAndUpdateCmd($AdGuardCmd, (($jsonAdGuardVer['core_update']===true)?1:0));
				$AdGuardCmd = $this->getCmd(null, 'hasUpdateWebInterface');
				$this->checkAndUpdateCmd($AdGuardCmd, (($jsonAdGuardVer['web_update']===true)?1:0));
				$AdGuardCmd = $this->getCmd(null, 'hasUpdateFTL');
				$this->checkAndUpdateCmd($AdGuardCmd, (($jsonAdGuardVer['FTL_update']===true)?1:0));
			}
			
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
		$status = $this->getCmd(null, 'status');
		if (!is_object($status)) {
			$status = new AdGuardcmd();
			$status->setLogicalId('status');
			$status->setIsVisible(1);
			$status->setOrder($order);
			$status->setName(__('Statut', __FILE__));
		}
		$status->setType('info');
		$status->setSubType('binary');
		$status->setEqLogic_id($this->getId());
		$status->setDisplay('generic_type', 'SWITCH_STATE');
		$status->save();
		
		$order++;
		$enable = $this->getCmd(null, 'enable');
		if (!is_object($enable)) {
			$enable = new AdGuardcmd();
			$enable->setLogicalId('enable');
			$enable->setDisplay('icon','<i class="fas fa-play"></i>');
			$enable->setIsVisible(1);
			$enable->setOrder($order);
			$enable->setName(__('Activer le filtrage', __FILE__));
		}
		$enable->setType('action');
		$enable->setSubType('other');
		$enable->setEqLogic_id($this->getId());
		$enable->setValue($status->getId());
		$enable->setDisplay('generic_type', 'SWITCH_ON');
		$enable->save();
		
		$order++;
		$disable = $this->getCmd(null, 'disable');
		if (!is_object($disable)) {
			$disable = new AdGuardcmd();
			$disable->setLogicalId('disable');
			$disable->setDisplay('icon','<i class="fas fa-stop"></i>');
			$disable->setIsVisible(1);
			$disable->setOrder($order);
			$disable->setName(__('Désactiver le filtrage', __FILE__));
		}
		$disable->setType('action');
		$disable->setSubType('other');
		$disable->setEqLogic_id($this->getId());
		$disable->setValue($status->getId());
		$disable->setDisplay('generic_type', 'SWITCH_OFF');
		$disable->save();
		
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

		$summaryRaw = AdGuard::getStructure('summaryRaw');
		
		foreach($summaryRaw as $id => $trad) {
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
			if(strpos($id,'percentage') !== false) $newCommand->setUnite( '%' );
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
		$hasUpdateWebInterface = $this->getCmd(null, 'hasUpdateWebInterface');
		if (!is_object($hasUpdateWebInterface)) {
			$hasUpdateWebInterface = new AdGuardcmd();
			$hasUpdateWebInterface->setLogicalId('hasUpdateWebInterface');
			$hasUpdateWebInterface->setIsVisible(1);
			$hasUpdateWebInterface->setOrder($order);
			$hasUpdateWebInterface->setName(__('Update InterfaceWeb Dispo', __FILE__));
		}
		$hasUpdateWebInterface->setType('info');
		$hasUpdateWebInterface->setSubType('binary');
		$hasUpdateWebInterface->setEqLogic_id($this->getId());
		$hasUpdateWebInterface->save();
		
		$order++;
		$hasUpdateFTL = $this->getCmd(null, 'hasUpdateFTL');
		if (!is_object($hasUpdateFTL)) {
			$hasUpdateFTL = new AdGuardcmd();
			$hasUpdateFTL->setLogicalId('hasUpdateFTL');
			$hasUpdateFTL->setIsVisible(1);
			$hasUpdateFTL->setOrder($order);
			$hasUpdateFTL->setName(__('Update FTL Dispo', __FILE__));
		}
		$hasUpdateFTL->setType('info');
		$hasUpdateFTL->setSubType('binary');
		$hasUpdateFTL->setEqLogic_id($this->getId());
		$hasUpdateFTL->save();
		
		$order++;
		$this->getAdGuardInfo(null,$order);
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
			$urlAdGuard = 'http://' . $ip . '/admin/api.php?status&summaryRaw';	
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
		$eqLogic->getAdGuardInfo($result);
	}

	/************************Getteur Setteur****************************/
}
?>
