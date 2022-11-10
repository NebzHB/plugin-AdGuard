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
	public static function serviceList() {
		$serviceList=self::getServicesList();
		if($serviceList !== null) { return $serviceList; }
		return [
			"9gag"=>"9Gag", 
			"amazon"=>"Amazon",
			"bilibili"=>"Bilibili",
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
	}
	
	public static function setServicesList($services) {
		// get existing services to compare with the new list, if different, update all eqLogics 
		$preServices=self::serviceList();
		$ret=false;
		if($services && is_array($services) && count($services) && count($preServices) != count($services)) {
			log::add('AdGuard', 'info', __('Des nouveaux services ont été ajoutés à AdGuard, mise à jour du cache des services et des commandes', __FILE__).'('.(count($services)-count($preServices)).')');
			exec(system::getCmdSudo() . 'chown -R www-data:www-data ' . dirname(__FILE__) . '/../../data/');
			exec(system::getCmdSudo() . 'chmod -R 775 ' . dirname(__FILE__) . '/../../data/');
			$ret = file_put_contents(dirname(__FILE__) . '/../../data/services.json', json_encode($services, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
			
			foreach (eqLogic::byType('AdGuard') as $AdGuard) {
				$AdGuard->save();
			}
		}
		
		return (($ret === false) ? false : true);
	}

	public static function getServicesList() {
		exec(system::getCmdSudo() . 'chown -R www-data:www-data ' . dirname(__FILE__) . '/../../data/');
		exec(system::getCmdSudo() . 'chmod -R 775 ' . dirname(__FILE__) . '/../../data/');
		exec('touch ' . dirname(__FILE__) . '/../../data/services.json');
		exec(system::getCmdSudo() . 'chown -R www-data:www-data ' . dirname(__FILE__) . '/../../data/');
		exec(system::getCmdSudo() . 'chmod -R 775 ' . dirname(__FILE__) . '/../../data/');
		
		return json_decode(file_get_contents(dirname(__FILE__) . '/../../data/services.json') , true);
	}
	
	public static function cron($_eqlogic_id = null) {
		$eqLogics = ($_eqlogic_id !== null) ? array(eqLogic::byId($_eqlogic_id)) : eqLogic::byType('AdGuard', true);
		foreach ($eqLogics as $AdGuard) {
			if($AdGuard->getConfiguration('type','AdGuardGlobal') != 'AdGuardGlobal') continue;
			$autorefresh = $AdGuard->getConfiguration('autorefresh','*/5 * * * *');
			if ($autorefresh != '') {
				try {
					$c = new Cron\CronExpression(checkAndFixCron($autorefresh), new Cron\FieldFactory);
					if ($c->isDue()) {
						$AdGuard->getAdGuardInfo(true);
					}
				} catch (Exception $exc) {
					log::add('AdGuard', 'error', __('Expression cron non valide pour ', __FILE__) . $AdGuard->getHumanName() . ' : ' . $autorefresh);
				}
			}
		}
	}	
	public static function cronDaily() {
		foreach (eqLogic::byType('AdGuard') as $AdGuard) {
			if($AdGuard->getConfiguration('type','') == 'AdGuardGlobal') $AdGuard->save();
		}
	}
	public static function nameExists($name,$objectId=null) {
		$allAdGuard = eqLogic::byObjectId($objectId,false);
		foreach ($allAdGuard as $u) {
			if ($name == $u->getName()) return true;
		}
		return false;
	}
	public static function createEq($eq,$event=true) {
		$eqp = eqlogic::byLogicalId($eq['logicalId'],'AdGuard');
		if (!is_object($eqp)){
			if($eq['name']) {
				if(AdGuard::nameExists($eq['name'],$eq['object_id'])) {
					$name=$eq['name'];
					$eq['name']=$eq['name'].'_'.$eq['serverName'];
					log::add('AdGuard', 'debug', "Nom en double " . $name . " renommé en " . $eq['name']);
				}
				log::add('AdGuard', 'info', 'Création de l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ')');
				$eqp = new AdGuard();
				$eqp->setEqType_name('AdGuard');
				if($eq['object_id']) $eqp->setObject_id($eq['object_id']);
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
				log::add('AdGuard', 'debug', 'Modification de l\'équipement ' . $eq['name'] .'('. $eq['logicalId'] . ')');	
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
						"num_replaced_parental"=>"Sites à contenu adulte bloqués",						
						"num_replaced_safesearch"=>"Recherches sécurisées forcées",
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
		$proto=$this->getConfiguration('proto','http');
		$ip = $this->getConfiguration('ip','');
		
		$url = $proto.'://' . $ip . '/control/'.$cmd;
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');
		
		if(!$ip || !$user || !$pass) return false;
		
		$request_http = new com_http($url,$user,$pass);
		$request_http->setNoSslCheck(true);
		$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		$params=((is_array($params))?json_encode($params):$params);
		if($params==null) {
			$request_http->setHeader(array(
				'Accept application/json, text/plain, */*'
			));
		} else {
			$request_http->setHeader(array(
				'Content-Type: application/json',
				'Accept application/json, text/plain, */*'
			));	
		}
		//$params=(($params==null)?[]:$params);
		$request_http->setPost($params);
				
		try {		
			log::add('AdGuard','info','Exécution commande '.$cmd);
			log::add('AdGuard','debug','Exécution commande '.$cmd.' avec params '.json_encode($params));
			$AdGuardinfo=$request_http->exec(10,1);
			if($AdGuardinfo) log::add('AdGuard','debug',"Retour brut : ".$AdGuardinfo);
		} catch (Exception $e) {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip $cmd ! Message : ".json_encode($e));
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '0');
			}
		}
		if(trim($AdGuardinfo) == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip $cmd, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '0');
			}
		}
		if(trim($AdGuardinfo) == "404 page not found") {
			log::add('AdGuard','error',"Impossible de communiquer POST avec le serveur AdGuard $ip $cmd, la commande n'existe pas ! Message : ".$AdGuardinfo);
		}
		
		return json_decode($AdGuardinfo,true);
	}
	
	public function getAdGuard($cmd,$params=null) {
		$proto=$this->getConfiguration('proto','http');
		$ip = $this->getConfiguration('ip','');
		
		$url = $proto.'://' . $ip . '/control/'.$cmd;
		$url.=(($params && count($params))?"?".http_build_query($params):'');
		
		$user = $this->getConfiguration('user','');
		$pass = $this->getConfiguration('password','');
		
		if(!$ip || !$user || !$pass) return false;
		
		$request_http = new com_http($url,$user,$pass);
		$request_http->setNoSslCheck(true);
		$request_http->setCURLOPT_HTTPAUTH(CURLAUTH_BASIC);
		$request_http->setHeader(array(
			'Content-Type: application/json',
			'Accept application/json, text/plain, */*'
		));
		$AdGuardinfo='';
		try {		
			$AdGuardinfo=$request_http->exec(10,1);
		} catch (Exception $e) {
			if($cmd != 'version.json') {
				log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip $cmd ! Message : ".json_encode($e));
				$online = $this->getCmd(null, 'online');
				if (is_object($online)) {
					$this->checkAndUpdateCmd($online, '0');
				}
			}
		}
		if(trim($AdGuardinfo) == "Forbidden") {
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip $cmd, vérifiez vos crédentials ! Message : ".$AdGuardinfo);
			$online = $this->getCmd(null, 'online');
			if (is_object($online)) {
				$this->checkAndUpdateCmd($online, '0');
			}
		}
		if(trim($AdGuardinfo) == "404 page not found") {
			log::add('AdGuard','error',"Impossible de communiquer GET avec le serveur AdGuard $ip $cmd, la commande n'existe pas ! Message : ".$AdGuardinfo);
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
		
		$temp_services_list=$this->getAdGuard('blocked_services/all');
		$AdGuardinfo['services_list']=[];
		if($temp_services_list && is_array($temp_services_list)) {
			foreach($temp_services_list['blocked_services'] as $i=>$s) {
				$AdGuardinfo['services_list'][$temp_services_list['blocked_services'][$i]['id']]=$temp_services_list['blocked_services'][$i]['name'];
			}
		}
		$temp_services_list=null;

		return $AdGuardinfo;
	}
	
	public function getAdGuardInfo($allowListServices=false) {
		if(!$this->getIsEnable()) return;
		try {
				
			$AdGuardinfo=$this->getAdGuardStatut();
			if(!$AdGuardinfo) return;

			log::add('AdGuard','info','Reçu info de AdGuard Home');
			log::add('AdGuard','debug','Reçu:'.json_encode($AdGuardinfo));
			
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
			// blocked_services
			$blocked_services = $this->getCmd(null, 'blocked_services');
			$this->checkAndUpdateCmd($blocked_services, str_replace(['"','[',']','null'],'',json_encode($AdGuardinfo['blocked_services'])));
			
			// write new servicesList if it's the cron only (to avoid infinite loop with postSave
			if($allowListServices) {
				self::setServicesList($AdGuardinfo['services_list']);
			}
			
			// internet_block
			$blocked_internet = $this->getCmd(null, 'blocked_internet');
			$blockString='||*^$important';
			$filtering_status=$AdGuardinfo['filtering'];
			if(!is_array($filtering_status['user_rules'])) $filtering_status['user_rules']=[];
			$ruleList=implode("\n",$filtering_status['user_rules']);
			if(strpos($ruleList,$blockString) !== false) {
				$this->checkAndUpdateCmd($blocked_internet, 1);
			} else {
				$this->checkAndUpdateCmd($blocked_internet, 0);
			}
			
			// stats
			$stats = AdGuard::getStructure('stats');
			foreach($stats as $id => $trad) {
				$AdGuardCmd = $this->getCmd(null, $id);
				if(strpos($id,'avg_processing_time') !== false) $AdGuardinfo['stats'][$id]=round($AdGuardinfo['stats'][$id]*1000,0);
				$this->checkAndUpdateCmd($AdGuardCmd, $AdGuardinfo['stats'][$id]);
			}
			
			// updates
			if($AdGuardinfo['version'] !== null && !$AdGuardinfo['version']['disabled']) {
				if($AdGuardinfo['version']['can_autoupdate']) { // if new version -> update new_version number
					$newVersion = $this->getCmd(null, 'newVersion');
					$this->checkAndUpdateCmd($newVersion, $AdGuardinfo['version']['new_version']);
				} else { // update current version number
					$currentVersion = $this->getCmd(null, 'currentVersion');
					$this->checkAndUpdateCmd($currentVersion, $AdGuardinfo['version']['new_version']);
					$newVersion = $this->getCmd(null, 'newVersion');
					$this->checkAndUpdateCmd($newVersion, '');
				}
				$hasUpdateAdGuard = $this->getCmd(null, 'hasUpdateAdGuard');
				$this->checkAndUpdateCmd($hasUpdateAdGuard, (($AdGuardinfo['version']['can_autoupdate']===true)?1:0));
			}elseif($AdGuardinfo['version'] === null) {
				$currentVersion = $this->getCmd(null, 'currentVersion');
				$this->checkAndUpdateCmd($currentVersion, __("Inconnu", __FILE__));
				$newVersion = $this->getCmd(null, 'newVersion');
				$this->checkAndUpdateCmd($newVersion, '');
				$hasUpdateAdGuard = $this->getCmd(null, 'hasUpdateAdGuard');
				$this->checkAndUpdateCmd($hasUpdateAdGuard, 0);
				log::add('AdGuard','info','version.json pas disponible sur AdGuard, version inconnue');
			}
			// clients
			if(is_array($AdGuardinfo['clients']['clients'])) {
				foreach($AdGuardinfo['clients']['clients'] as $client) {
					$eqp = eqLogic::byLogicalId($this->getId().'-'.$client['name'],'AdGuard');
					
					if(is_object($eqp)) {
						// client_ids
						$client_ids = $eqp->getCmd(null, 'client_ids');
						$eqp->checkAndUpdateCmd($client_ids, str_replace(['"','[',']'],'',json_encode($client['ids'])));
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
						// client_blocked_services
						$client_blocked_services = $eqp->getCmd(null, 'client_blocked_services');
						$eqp->checkAndUpdateCmd($client_blocked_services, str_replace(['"','[',']','null'],'',json_encode($client['blocked_services'])));
						// client_blocked_internet
						$client_blocked_internet = $eqp->getCmd(null, 'client_blocked_internet');
						
						$name=addcslashes(addslashes($client['name']), ',|');
						$blockString="||*^\$client='".$name."',important";
						$filtering_status=$AdGuardinfo['filtering'];
						$ruleList=implode("\n",$filtering_status['user_rules']);
						if(strpos($ruleList,$blockString) !== false) {
							$eqp->checkAndUpdateCmd($client_blocked_internet, 1);
						} else {
							$eqp->checkAndUpdateCmd($client_blocked_internet, 0);
						}
					} 
				}
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
	
	public function createCmd($cmd, $order) {

		$newCmd = $this->getCmd(null, $cmd['logicalId']);
		if (!is_object($newCmd)) {
			log::add('AdGuard', 'info', 'Création commande:' . $cmd['logicalId']);
			$newCmd = new AdGuardCmd();
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
				if($configuration_type == 'listValue' && strpos($cmd['logicalId'],'service_') !== false) {
					$list=[];
					foreach(AdGuard::serviceList() as $val => $label) {
						array_push($list,$val.'|'.$label);
					}
					$configuration_value=join(';',$list);
				}
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
		if ($this->getConfiguration('type','') == 'AdGuardGlobal'){
			return 'plugins/AdGuard/plugin_info/AdGuard_icon.png';
		}else {
			return 'plugins/AdGuard/plugin_info/AdGuard_user.png';
		}
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
			
			$clientList=[];
			$clients=$this->getAdGuard('clients');
			if($clients && $clients['clients'] && is_array($clients['clients'])) {
				foreach($clients['clients'] as $client) {
					$eq = [
						"name"=>$client['name'],
						"logicalId"=>$this->getId().'-'.$client['name'],
						"enable"=>1,
						"visible"=>1,
						"object_id"=>$this->getObject_id(),
						"configuration"=>[
							"server"=>$this->getId(),
							"type"=>'Client'
						],
						"serverName"=>$this->getName()
					];
					self::createEq($eq);
					array_push($clientList,$this->getId().'-'.$client['name']);
				}
			}
			$eqLogics = eqLogic::byType('AdGuard');
			foreach ($eqLogics as $eqLogic) {
				if($eqLogic->getConfiguration('type','') != 'Client') continue;
				if($eqLogic->getConfiguration('server','') != $this->getId()) continue;
				
				if(!in_array($eqLogic->getLogicalId(),$clientList)) {
					log::add('AdGuard','info','Pas trouvé dans la liste de clients de AdGuard : '.$eqLogic->getLogicalId().' -> désactivation de l\'équipement');
					$eqLogic->setIsEnable(0);
					$eqLogic->save(true);
				}
			}
			
			$this->getAdGuardInfo(false);
		}
	}
	public function preRemove() {
		if($this->getConfiguration('type','') == "AdGuardGlobal") {
			$eqLogics = eqLogic::byType('AdGuard');
			foreach ($eqLogics as $eqLogic) {
				if($eqLogic->getConfiguration('type','') != "Client") continue;
				
				if($eqLogic->getConfiguration('server','') == $this->getId()) { // if this bridgedAccessory logicalId contains this bridge logicalId
					$eqLogic->remove();
				}
			}
		}
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
		if($type == "Client") {
			$serverId = $eqLogic->getConfiguration('server','');
			if($serverId) {
				$AdGuard=eqlogic::byId($serverId);
			}
		} else {
			$AdGuard=$eqLogic;
		}
		$logical = $this->getLogicalId();
		$cmd=null;
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
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$params = ["enabled" => true,"interval"=> $filtering_status['interval']];
				break;
				case 'filtering_disable':
					$cmd = 'filtering/config';
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$params = ["enabled" => false,"interval"=> $filtering_status['interval']];
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
				case 'service_block':
					if($_options['select'] == "") break;
					$blocked_services=$AdGuard->getAdGuard('blocked_services/list');
					array_push($blocked_services,$_options['select']);
					$new_blocked_services=array_unique($blocked_services,SORT_STRING);
					$cmd='blocked_services/set';
					$params=$new_blocked_services;
				break;
				case 'service_unblock':
					$blocked_services=$AdGuard->getAdGuard('blocked_services/list');
					if (($key = array_search($_options['select'], $blocked_services)) !== false) {
						array_splice($blocked_services,$key,1);
						$cmd='blocked_services/set';
						$params=$blocked_services;
					}
				break;
				case 'services_block':
					$cmd='blocked_services/set';
					$params=array_keys(AdGuard::serviceList());
				break;
				case 'services_unblock':
					$cmd='blocked_services/set';
					$params=[];
				break;
				case 'internet_block':
					$blockString='||*^$important';
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$ruleList=implode("\n",$filtering_status['user_rules']);
					if(count($filtering_status['user_rules'])) {
						$blockString.="\n";
					}
					$cmd="filtering/set_rules";
					$params=$blockString.$ruleList;
				break;
				case 'internet_unblock':
					$blockString='||*^$important';
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$ruleList=implode("\n",$filtering_status['user_rules']);
					if(strpos($ruleList,$blockString."\n") !== false) {
						$blockString.="\n";
					}
					$cmd="filtering/set_rules";
					$params=str_replace($blockString,"",$ruleList);
					if($params == "") $params=[];
				break;
				case 'add_custom_rule':
					$blockString=$_options['message'];
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$ruleList=implode("\n",$filtering_status['user_rules']);
					if(count($filtering_status['user_rules'])) {
						$blockString.="\n";
					}
					$cmd="filtering/set_rules";
					$params=$blockString.$ruleList;
				break;
				case 'del_custom_rule':
					$blockString=$_options['message'];
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$ruleList=implode("\n",$filtering_status['user_rules']);
					if(strpos($ruleList,$blockString."\n") !== false) {
						$blockString.="\n";
					}
					$cmd="filtering/set_rules";
					$params=str_replace($blockString,"",$ruleList);
					if($params == "") $params=[];
				break;
				
				// block everything for a client (first rule !) : ||*^$client='Nebz iPhone',important 
				// Use the backslash (\) to escape quotes (" and '), commas (,), and pipes (|) in client name
				
				// CLIENT
				case 'client_use_global_settings_enable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['use_global_settings']=true;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_use_global_settings_disable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['use_global_settings']=false;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_filtering_enable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['filtering_enabled']=true;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_filtering_disable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['filtering_enabled']=false;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_safebrowsing_enable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['safebrowsing_enabled']=true;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_safebrowsing_disable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['safebrowsing_enabled']=false;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_parental_enable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['parental_enabled']=true;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_parental_disable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['parental_enabled']=false;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_safesearch_enable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['safesearch_enabled']=true;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_safesearch_disable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['safesearch_enabled']=false;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_use_global_blocked_services_enable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['use_global_blocked_services']=true;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_use_global_blocked_services_disable':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['use_global_blocked_services']=false;
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_service_block':
					if($_options['select'] == "") break;
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							if(!is_array($client['blocked_services'])) $client['blocked_services']=[];
							array_push($client['blocked_services'],$_options['select']);
							$client['blocked_services']=array_unique($client['blocked_services'],SORT_STRING);
							$cmd='clients/update';
							$params=["name"=>$client['name'],"data"=>$client];
						}
					}
				break;
				case 'client_service_unblock':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							if (($key = array_search($_options['select'], $client['blocked_services'])) !== false) {
								array_splice($client['blocked_services'],$key,1);
								$cmd='clients/update';
								$params=["name"=>$client['name'],"data"=>$client];
								break;
							}
						}
					}
				break;
				case 'client_services_block':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['blocked_services']=array_keys(AdGuard::serviceList());
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_services_unblock':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							$client['blocked_services']=[];
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_internet_block':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=addcslashes(addslashes($name[1]), ',|');
					$blockString="||*^\$client='".$name."',important";
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$ruleList=implode("\n",$filtering_status['user_rules']);
					$cmd="filtering/set_rules";
					if(count($filtering_status['user_rules'])) {
						$blockString.="\n";
					}
					$params=$blockString.$ruleList;
				break;
				case 'client_internet_unblock':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=addcslashes(addslashes($name[1]), ',|');
					$blockString="||*^\$client='".$name."',important";
					$filtering_status=$AdGuard->getAdGuard('filtering/status');
					$ruleList=implode("\n",$filtering_status['user_rules']);
					if(strpos($ruleList,$blockString."\n") !== false) {
						$blockString.="\n";
					}
					$cmd="filtering/set_rules";
					$params=str_replace($blockString,"",$ruleList);
					if($params == "") $params=[];
				break;
				case 'client_ids_add':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							$cmd='clients/update';
							if(count($client['ids']) == 1 && strpos($client['ids'][0], 'notused') !== false) $client['ids']=[]; // was a not used client
							array_push($client['ids'],$_options['message']);
							$params=["name"=>$client['name'],"data"=>$client];
							break;
						}
					}
				break;
				case 'client_ids_del':
					$name=explode('-',$eqLogic->getLogicalId());
					$name=$name[1];
					$clients=$AdGuard->getAdGuard('clients');
					foreach($clients['clients'] as $client) {
						if($client['name'] == $name) {
							if (($key = array_search($_options['message'], $client['ids'])) !== false) {
								array_splice($client['ids'],$key,1);
								if(count($client['ids']) == 0) array_push($client['ids'],'notused'.str_pad(rand(0,1000),4,0,STR_PAD_LEFT)); // is a not used client
								$cmd='clients/update';
								$params=["name"=>$client['name'],"data"=>$client];
							}
							break;
						}
					}
				break;
				/*
				@@||app-measurement.com^$important
				@@||www.littlefabrics.com^$important
				@@||self.events.data.microsoft.com^$important
				*/
			}
			
			if(!$cmd) return false;
			
			$AdGuardinfo=$AdGuard->postAdGuard($cmd,$params);
			if($sleep) sleep($sleep);
		}
		
		$AdGuard->getAdGuardInfo(true);
	}

	/************************Getteur Setteur****************************/
}
?>
