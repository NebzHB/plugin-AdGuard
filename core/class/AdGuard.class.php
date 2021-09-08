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
	public static $serviceList = [
		"9gag"=>"9Gag", 
		"amazon"=>"Amazon", 
		"cloudflare"=>"CloudFlare", 
		"dailymotion"=>"Dailymotion", 
		"discord"=>"Discord", 
		"disneyplus"=>"Disney+", 
		"ebay"=>"EBay", 
		"epic_games"=>"Epic Games", 
		"facebook"=>"Facebook", 
		"hulu"=>"Hulu", 
		"imgur"=>"Imgur", 
		"instagram"=>"Instagram", 
		"mail_ru"=>"Mail.ru", 
		"netflix"=>"Netflix", 
		"ok"=>"OK.ru", 
		"origin"=>"Origin", 
		"pinterest"=>"Pinterest", 
		"qq"=>"QQ", 
		"reddit"=>"Reddit", 
		"skype"=>"Skype", 
		"snapchat"=>"Snapchat", 
		"spotify"=>"Spotify", 
		"steam"=>"Steam", 
		"telegram"=>"Telegram", 
		"tiktok"=>"TikTok", 
		"tinder"=>"Tinder", 
		"twitch"=>"Twitch", 
		"twitter"=>"Twitter", 
		"viber"=>"Viber", 
		"vimeo"=>"Vimeo", 
		"vk"=>"VK.com", 
		"wechat"=>"WeChat", 
		"weibo"=>"Weibo", 
		"whatsapp"=>"WhatsApp", 
		"youtube"=>"YouTube"
	];
	
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
	
	public static function createEq($eq,$event=true) {
		$eqp = eqlogic::byLogicalId($eq['logicalId'],'AdGuard');
		if (!is_object($eqp)){
			if($eq['name']) {
				log::add('AdGuard', 'info', 'Création de l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ')');
				$eqp = new AdGuard();
				$eqp->setEqType_name('AdGuard');
				$eqp->setLogicalId($eq['logicalId']);
				$eqp->setName($eq['name']);
				foreach($eq['configuration'] as $c => $v) {
					$eqp->setConfiguration($c, $v);
				}
				$eqp->setConfiguration('toRemove',0);
				$eqp->setIsEnable($eq['enable']);
				$eqp->setIsVisible($eq['visible']);
				$eqp->save(false);
				if($event) event::add('AdGuard::includeDevice');
			} else {
				log::add('AdGuard', 'warning', 'Etrange l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ') n\'a pas de nom... vérifiez dans AdGuard : '.json_encode($eq));
			}
		} else {
			if($eq['name']) {
				log::add('AdGuard', 'info', 'Modification de l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ')');	
				foreach($eq['configuration'] as $c => $v) {
					$eqp->setConfiguration($c, $v);
				}
				$eqp->setConfiguration('toRemove',0);
				$eqp->save(true);
			} else {
				log::add('AdGuard', 'warning', 'Etrange l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ') n\'a pas de nom... vérifiez dans AdGuard : '.json_encode($eq));
			}
		}
		return $eqp;
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
			log::add('AdGuard','debug',"raw return : ".$AdGuardinfo);
		} catch (Exception $e) {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip ! Message : ".json_encode($e));
		}
		if(trim($AdGuardinfo) == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
		}
		if(trim($AdGuardinfo) == "404 page not found") {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip, la commande n'existe pas ! Message : ".$AdGuardinfo);
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
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip ! Message : ".json_encode($e));
		}
		if(trim($AdGuardinfo) == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
		}
		if(trim($AdGuardinfo) == "404 page not found") {
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip, la commande n'existe pas ! Message : ".$AdGuardinfo);
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
		$AdGuardinfo['blocked_services']=$this->getAdGuard('blocked_services/list');

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
			
			// clients
			foreach($AdGuardinfo['clients']['clients'] as $client) {
				$eqp = eqLogic::byLogicalId($client['name'],'AdGuard');
				// filtering
				$client_filtering_enabled = $eqp->getCmd(null, 'client_filtering_enabled');
				$eqp->checkAndUpdateCmd($client_filtering_enabled, (($client['filtering_enabled']===true)?1:0));
				// safebrowsing
				$client_safebrowsing_enabled = $eqp->getCmd(null, 'client_safebrowsing_enabled');
				$eqp->checkAndUpdateCmd($client_safebrowsing_enabled, (($client['safebrowsing_enabled']===true)?1:0));
				// parental
				$client_parental_enabled = $eqp->getCmd(null, 'client_parental_enabled');
				$eqp->checkAndUpdateCmd($client_parental_enabled, (($client['parental_enabled']===true)?1:0));
				// safesearch
				$client_safesearch_enabled = $eqp->getCmd(null, 'client_safesearch_enabled');
				$eqp->checkAndUpdateCmd($client_safesearch_enabled, (($client['safesearch_enabled']===true)?1:0));
				// client_use_global_blocked_services
				$client_use_global_blocked_services = $eqp->getCmd(null, 'client_use_global_blocked_services');
				$eqp->checkAndUpdateCmd($client_use_global_blocked_services, (($client['use_global_blocked_services']===true)?1:0));
				// client_use_global_settings
				$client_use_global_settings = $eqp->getCmd(null, 'client_use_global_settings');
				$eqp->checkAndUpdateCmd($client_use_global_settings, (($client['use_global_settings']===true)?1:0));
			}

			$this->setConfiguration('blocked_services',$AdGuardinfo['blocked_services']);
			$this->save(true);
			
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
		$type=$this->getConfiguration('type','');
		//if($type != 'AdGuardGlobal') return true;
		
		$order=0;
		$device = self::devicesParameters($type);
	
		foreach($device['commands'] as $cmd) {
			$order++;
			$this->createCmd($cmd,$order);
		}
		
		if($type == 'AdGuardGlobal') {
			// stats
			$stats = self::getStructure('stats');
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
			
			$clients=$this->getAdGuard('clients');
			foreach($clients['clients'] as $client) {
				$eq = [
					"name"=>$client['name'],
					"logicalId"=>$client['name'],
					"enable"=>1,
					"visible"=>1,
					"configuration"=>[
						"server"=>$this->getId(),
						"type"=>'Client'
					]
				];
				self::createEq($eq);
			}
			
			$this->getAdGuardInfo();
		} /*else {
			$serverId=$this->getConfiguration('server',null);
			if($serverId) {
				$eqLogic=eqlogic::byId($serverId);
			}
		}*/
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
		$type = $eqLogic->getConfiguration('type','');
		$logical = $this->getLogicalId();
		$params=null;
		$sleep=null;
		if ($logical != 'refresh'){
			switch ($logical) {
				case 'protection_disable':
					$cmd = 'dns_config';
					$params = ["protection_enabled" => false];
				break;
				case 'protection_enable':
					$cmd = 'dns_config';
					$params = ["protection_enabled" => true];
				break;
				case 'UpdateAdGuard':
					$cmd = 'update';
					$sleep=1;
				break;
				case 'filtering_enable':
					$cmd = 'filtering/config';
					$params = ["enabled" => true];
				break;
				case 'filtering_disable':
					$cmd = 'filtering/config';
					$params = ["enabled" => false];
				break;
				case 'safebrowsing_enable':
					$cmd = 'safebrowsing/enable';
				break;
				case 'safebrowsing_disable':
					$cmd = 'safebrowsing/disable';
				break;
				case 'parental_enable':
					$cmd = 'parental/enable';
				break;
				case 'parental_disable':
					$cmd = 'parental/disable';
				break;
				case 'safesearch_enable':
					$cmd = 'safesearch/enable';
				break;
				case 'safesearch_disable':
					$cmd = 'safesearch/disable';
				break;
				case 'reset_stats':
					$cmd = 'stats_reset';
				break;
				// block everything for a client (first rule !) : ||*^$client='Nebz iPhone',important 
				// Use the backslash (\) to escape quotes (" and '), commas (,), and pipes (|) in client name
			}
			
			if($type == 'AdGuardGlobal') {
				$AdGuardinfo=$eqLogic->postAdGuard($cmd,$params);
				log::add('AdGuard','debug','Exec '.$cmd.' avec params '.json_encode($params).' '.$AdGuardinfo);
				if($sleep) sleep($sleep);
			} else {
				$serverId = $eqLogic->getConfiguration('server','');
				if($serverId) {
					$eqLogicServer=eqlogic::byId($serverId);
					$AdGuardinfo=$eqLogicServer->postAdGuard($cmd,$params);
					log::add('AdGuard','debug','Exec '.$cmd.' avec params '.json_encode($params).' '.$AdGuardinfo);
					if($sleep) sleep($sleep);
				}
			}
		}
		
		if($type == 'AdGuardGlobal') {
			$eqLogic->getAdGuardInfo();
		} else {
			$serverId = $eqLogic->getConfiguration('server','');
			if($serverId) {
				$eqLogicServer=eqlogic::byId($serverId);
				$eqLogicServer->getAdGuardInfo();
			}
		}
	}

	/************************Getteur Setteur****************************/
}
?>
