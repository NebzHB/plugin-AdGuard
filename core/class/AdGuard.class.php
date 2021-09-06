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
			if($AdGuard->getConfiguration('type','AdGuardGlobal') != 'AdGuardGlobal') continue;
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
	
	public static function getStructure($name) {
	
		switch($name) {
			case "stats" :
				return ["num_dns_queries"=>"Requêtes DNS",
						"num_blocked_filtering"=>"Bloqués par Filtres",
						"num_replaced_safebrowsing"=>"Tentatives de malware-hameçonnage bloquées",
						"num_replaced_safesearch"=>"Recherches sécurisées forcées",
						"num_replaced_parental"=>"Sites à contenu adulte bloqués",
						"avg_processing_time"=>"Temps moyen de traitement"
					];
			break;
		}		
	}
	
	public static function devicesParameters($type = '') {
		$path = dirname(__FILE__) . '/../config/devices/' . $type;

		if (!is_dir($path)) {
			return false;
		}
		try {
			$file = $path . '/' . $type.'.json';
			$content = file_get_contents($file);
			$return = json_decode($content, true);
		} catch (Exception $e) {
			return false;
		}
		
        	return $return;
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
			'Accept application/json, text/plain, */*'
		));
		$request_http->setPost(json_encode($params));
				
		try {		
			$AdGuardinfo=$request_http->exec(10,1);
		} catch (Exception $e) {
			log::add('AdGuard','error',"Impossible de communiquer avec le serveur AdGuard $ip ! Message : ".json_encode($e));
		}
		if($AdGuardinfo == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer avec le serveur AdGuard $ip, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
		}
		
		return json_decode($AdGuardinfo,true);
	}
	
	public function getAdGuard($cmd,$params=null) {
		$ip = $this->getConfiguration('ip','');
		
		$url = 'http://' . $ip . '/control/'.$cmd;
		$url.=(($params && count($params))?"?".http_build_query($params):'');
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');
		
		$request_http = new com_http($url,$user,$pass);
		$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		$request_http->setHeader(array(
			'Content-Type: application/json',
			'Accept application/json, text/plain, */*'
		));
		
		try {		
			$AdGuardinfo=$request_http->exec(10,1);
		} catch (Exception $e) {
			log::add('AdGuard','error',"Impossible de communiquer avec le serveur AdGuard $ip ! Message : ".json_encode($e));
		}
		if($AdGuardinfo == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer avec le serveur AdGuard $ip, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
		}
		
		return json_decode($AdGuardinfo,true);
	}
	
	public function getAdGuardStatut() {
		$AdGuardinfo=$this->getAdGuard('status');
		if(!$AdGuardinfo) return false;
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
		$AdGuardinfo['clients']=$this->getAdGuard('clients');
		$AdGuardinfo['clients']['auto_clients']="deleted";
		$AdGuardinfo['clients']['supported_tags']="deleted";

		return $AdGuardinfo;
	}
	
	public function getAdGuardInfo() {
		if(!$this->getIsEnable()) return;
		try {
				
			$AdGuardinfo=$this->getAdGuardStatut();
			if(!$AdGuardinfo) return;

			log::add('AdGuard','debug','recu:'.json_encode($AdGuardinfo));
			
			$protection_enabled = $this->getCmd(null, 'protection_enabled');
			$this->checkAndUpdateCmd($protection_enabled, (($AdGuardinfo['protection_enabled']===true)?1:0));
			
			// filtering
			$filtering_enabled = $this->getCmd(null, 'filtering_enabled');
			$this->checkAndUpdateCmd($filtering_enabled, (($AdGuardinfo['filtering']['enabled']===true)?1:0));
			// safebrowsing
			$safebrowsing_enabled = $this->getCmd(null, 'safebrowsing_enabled');
			$this->checkAndUpdateCmd($safebrowsing_enabled, (($AdGuardinfo['safebrowsing']['enabled']===true)?1:0));
			// parental
			$parental_enabled = $this->getCmd(null, 'parental_enabled');
			$this->checkAndUpdateCmd($parental_enabled, (($AdGuardinfo['parental']['enabled']===true)?1:0));
			// safesearch
			$safesearch_enabled = $this->getCmd(null, 'safesearch_enabled');
			$this->checkAndUpdateCmd($safesearch_enabled, (($AdGuardinfo['safesearch']['enabled']===true)?1:0));
			
			// stats
			$stats = AdGuard::getStructure('stats');
			foreach($stats as $id => $trad) {
				$AdGuardCmd = $this->getCmd(null, $id);
				if(strpos($id,'avg_processing_time') !== false) $AdGuardinfo['stats'][$id]=round($AdGuardinfo['stats'][$id]*1000,0);
				$this->checkAndUpdateCmd($AdGuardCmd, $AdGuardinfo['stats'][$id]);
			}
			
			// updates
			$hasUpdateAdGuard = $this->getCmd(null, 'hasUpdateAdGuard');
			$this->checkAndUpdateCmd($hasUpdateAdGuard, (($AdGuardinfo['version']['can_autoupdate']===true)?1:0));

			
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
	
	public function createCmd($cmd, $order) {

		//if (strlen($cmd['name']) > 45) $cmd['name'] = substr($cmd['name'], 0, 45);

		$newCmd = $this->getCmd(null, $cmd['logicalId']);
		if (!is_object($newCmd)) {
			log::add('AdGuard', 'debug', 'Création commande:' . $cmd['logicalId']);
			$newCmd = new unifiCmd();
			$newCmd->setLogicalId($cmd['logicalId']);
			$newCmd->setIsVisible($cmd['isVisible']);
			$newCmd->setOrder($order);
			$newCmd->setName(__($cmd['name'], __FILE__));
			$newCmd->setEqLogic_id($this->getId());
		}
		else {
			log::add('AdGuard', 'debug', 'Modification commande:' . $cmd['logicalId']);
		}
		if (isset($cmd['unit'])) {
			$newCmd->setUnite($cmd['unit']);
		}
		$newCmd->setType($cmd['type']);
		if (isset($cmd['configuration'])) {
			foreach ($cmd['configuration'] as $configuration_type => $configuration_value) {
				$newCmd->setConfiguration($configuration_type, $configuration_value);
			}
		}
		if (isset($cmd['template'])) {
			foreach ($cmd['template'] as $template_type => $template_value) {
				$newCmd->setTemplate($template_type, $template_value);
			}
		}
		if (isset($cmd['display'])) {
			foreach ($cmd['display'] as $display_type => $display_value) {
				if ($display_type == "generic_type") {
					$newCmd->setGeneric_type($display_value);
				}
				else {
					if ($newCmd->getDisplay($display_type) == "") {
						$newCmd->setDisplay($display_type, $display_value);
					}
				}
			}
		}
		$newCmd->setSubType($cmd['subtype']);
		if ($cmd['type'] == 'action' && isset($cmd['value'])) {
			$linkStatus = $this->getCmd(null, $cmd['value']);
			if (is_object($linkStatus)) $newCmd->setValue($linkStatus->getId());
		}
		$newCmd->save();
	}
	
	public function getImage(){
		return 'plugins/AdGuard/plugin_info/AdGuard_icon.png';
	}
	
	public function preSave() {
		if ($this->getConfiguration('type','') == ''){
			$this->setConfiguration('type','AdGuardGlobal');
		}
	}

	public function postSave() {
		
		if($this->getConfiguration('type','') != 'AdGuardGlobal') return true;
		
		$order=0;
		$device = self::devicesParameters('AdGuardGlobal');
	
		foreach($device['commands'] as $cmd) {
			$order++;
			$this->createCmd($cmd,$order);
		}
		
		// stats
		$stats = AdGuard::getStructure('stats');
		foreach($stats as $id => $trad) {
			$order++;
			$cmd = [
				"name" => $trad,
				"type" => 'info',
				"subtype" => 'numeric',
				"template" => [
					"dashboard" => 'line',
					"mobile" => 'line'
				],
				"display" => [
					"generic_type" => 'GENERIC_INFO'
				],
				"isVisible"=> 1,
				"isHistorized"=> 0,
				"logicalId"=> $id
			];
			if(strpos($id,'avg_processing_time') !== false) $cmd['unit']='ms';
			$this->createCmd($cmd,$order);		
		}
		
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
