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

if (!isConnect('admin')) {
	throw new Exception('401 Unauthorized');
}
$eqLogics = AdGuard::byType('AdGuard');
?>

<table class="table table-condensed tablesorter" id="table_healthAdGuard">
	<thead>
		<tr>
			<th>{{Equipement}}</th>
			<th>{{ID}}</th>
			<th>{{Type}}</th>
			<th>{{Adresse IP}}</th>
			<th>{{Update dispo ?}}</th>
			<th>{{Protection ?}}</th>
			<th>{{Filtrage ?}}</th>
			<th>{{SafeBrowsing ?}}</th>
			<th>{{Parental ?}}</th>
			<th>{{SafeSearch ?}}</th>
			<th>{{Services ?}}</th>
			<th>{{DNS Bloqué ?}}</th>
			<th>{{En Ligne}}</th>
			<th>{{Date création}}</th>
		</tr>
	</thead>
	<tbody>
	 <?php

foreach ($eqLogics as $eqLogic) {
	$type=$eqLogic->getConfiguration('type');
	if($type == 'Client') continue;
	displayHealthLine($eqLogic);
	foreach ($eqLogics as $Client) {
		$Bridgedtype=$Client->getConfiguration('type');
		if($Bridgedtype != 'Client') continue;
		if($Client->getConfiguration('server') == $eqLogic->getId()) {
			displayHealthLine($Client,'<i class="fas fa-level-up-alt fa-rotate-90"></i>&nbsp;&nbsp;');
		}
	}
}

function displayHealthLine($eqLogic,$tab='') {
	$type=$eqLogic->getConfiguration('type');
	if($eqLogic->getIsEnable()) {
		echo '<tr>';
	} else {
		echo '<tr style="background-color:lightgrey !important;">';
	}
	echo '<td>'.$tab.'<a href="' . $eqLogic->getLinkToConfiguration() . '" style="text-decoration: none;">' . $eqLogic->getHumanName(true) . ((!$eqLogic->getIsvisible())?'&nbsp;<i class="fas fa-eye-slash"></i>':''). '</a></td>';
	echo '<td><span class="label label-info" style="font-size : 1em;width:100%">' . $eqLogic->getId() . '</span></td>';
	echo '<td><span class="label label-info" style="font-size : 1em;width:100%">' . $type . '</span></td>';
	echo '<td><span class="label label-info" style="font-size : 1em;width:100%">' . $eqLogic->getConfiguration('ip') . '</span></td>';
	$hasUpdateAdGuard = $eqLogic->getCmd(null, 'hasUpdateAdGuard');
	if (is_object($hasUpdateAdGuard)) {
		$hasUpdateAdGuard = $hasUpdateAdGuard->execCmd();
		if($hasUpdateAdGuard == 1) {
			$hasUpdateAdGuard_status='<span class="label label-warning" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$hasUpdateAdGuard_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$hasUpdateAdGuard_status='<span class="label label-primary" style="font-size : 1em; cursor : default;width:100%">{{Client}}</span>';
	}
	echo '<td>' . $hasUpdateAdGuard_status . '</td>';
	
	$protection_enabled = $eqLogic->getCmd(null, 'protection_enabled');
	if (is_object($protection_enabled)) {
		$protection_enabled = $protection_enabled->execCmd();
		if($protection_enabled == 1) {
			$protection_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$protection_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$protection_enabled_status='<span class="label label-primary" style="font-size : 1em; cursor : default;width:100%">{{Client}}</span>';
	}
	echo '<td>' . $protection_enabled_status . '</td>';
	
	$filtering_enabled = $eqLogic->getCmd(null, 'filtering_enabled');
	if (is_object($filtering_enabled)) {
		$filtering_enabled = $filtering_enabled->execCmd();
		if($filtering_enabled == 1) {
			$filtering_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$filtering_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$client_filtering_enabled = $eqLogic->getCmd(null, 'client_filtering_enabled');
		if (is_object($client_filtering_enabled)) {
			$client_filtering_enabled = $client_filtering_enabled->execCmd();
			if($client_filtering_enabled == 1) {
				$filtering_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
			} else {
				$filtering_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
			}
		}
	}
	echo '<td>' . $filtering_enabled_status . '</td>';
	
	$safebrowsing_enabled = $eqLogic->getCmd(null, 'safebrowsing_enabled');
	if (is_object($safebrowsing_enabled)) {
		$safebrowsing_enabled = $safebrowsing_enabled->execCmd();
		if($safebrowsing_enabled == 1) {
			$safebrowsing_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$safebrowsing_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$client_safebrowsing_enabled = $eqLogic->getCmd(null, 'client_safebrowsing_enabled');
		if (is_object($client_safebrowsing_enabled)) {
			$client_safebrowsing_enabled = $client_safebrowsing_enabled->execCmd();
			if($client_safebrowsing_enabled == 1) {
				$safebrowsing_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
			} else {
				$safebrowsing_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
			}
		}
	}
	echo '<td>' . $safebrowsing_enabled_status . '</td>';
	
	$parental_enabled = $eqLogic->getCmd(null, 'parental_enabled');
	if (is_object($parental_enabled)) {
		$parental_enabled = $parental_enabled->execCmd();
		if($parental_enabled == 1) {
			$parental_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$parental_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$client_parental_enabled = $eqLogic->getCmd(null, 'client_parental_enabled');
		if (is_object($client_parental_enabled)) {
			$client_parental_enabled = $client_parental_enabled->execCmd();
			if($client_parental_enabled == 1) {
				$parental_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
			} else {
				$parental_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
			}
		}
	}
	echo '<td>' . $parental_enabled_status . '</td>';
	
	$safesearch_enabled = $eqLogic->getCmd(null, 'safesearch_enabled');
	if (is_object($safesearch_enabled)) {
		$safesearch_enabled = $safesearch_enabled->execCmd();
		if($safesearch_enabled == 1) {
			$safesearch_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$safesearch_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$client_safesearch_enabled = $eqLogic->getCmd(null, 'client_safesearch_enabled');
		if (is_object($client_safesearch_enabled)) {
			$client_safesearch_enabled = $client_safesearch_enabled->execCmd();
			if($client_safesearch_enabled == 1) {
				$safesearch_enabled_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
			} else {
				$safesearch_enabled_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
			}
		}
	}
	echo '<td>' . $safesearch_enabled_status . '</td>';

	$blocked_services = $eqLogic->getCmd(null, 'blocked_services');
	if (is_object($blocked_services)) {
		$blocked_services = $blocked_services->execCmd();
		if($blocked_services != '[]' && $blocked_services != 'null') {
			$blocked_services_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%" title="'.$blocked_services.'">{{OUI}}</span>';
		} else {
			$blocked_services_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$client_blocked_services = $eqLogic->getCmd(null, 'client_blocked_services');
		if (is_object($client_blocked_services)) {
			$client_blocked_services = $client_blocked_services->execCmd();
			if($client_blocked_services != '[]' && $client_blocked_services != 'null') {
				$blocked_services_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%" title=\''.$client_blocked_services.'\'>{{OUI}}</span>';
			} else {
				$blocked_services_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
			}
		}
	}
	echo '<td>' . $blocked_services_status . '</td>';
	
	$blocked_internet = $eqLogic->getCmd(null, 'blocked_internet');
	if (is_object($blocked_internet)) {
		$blocked_internet = $blocked_internet->execCmd();
		if($blocked_internet == 1) {
			$blocked_internet_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
		} else {
			$blocked_internet_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
		}
	} else {
		$client_blocked_internet = $eqLogic->getCmd(null, 'client_blocked_internet');
		if (is_object($client_blocked_internet)) {
			$client_blocked_internet = $client_blocked_internet->execCmd();
			if($client_blocked_internet == 1) {
				$blocked_internet_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{OUI}}</span>';
			} else {
				$blocked_internet_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{NON}}</span>';
			}
		}
	}
	echo '<td>' . $blocked_internet_status . '</td>';
	

	
	
	
	$onlineCmd = $eqLogic->getCmd(null, 'online');
	if (is_object($onlineCmd)) {
		$online = $onlineCmd->execCmd();
		if($online == 1) {
			$online_status='<span class="label label-success" style="font-size : 1em; cursor : default;width:100%">{{OK}}</span>';
		} else {
			$online_status='<span class="label label-danger" style="font-size : 1em; cursor : default;width:100%">{{KO}}</span>';
		}
	} else {
		$online_status='<span class="label label-primary" style="font-size : 1em; cursor : default;width:100%">{{Client}}</span>';
	}
	echo '<td>' . $online_status . '</td>';
	echo '<td><span class="label label-info" style="font-size : 1em;width:100%">' . $eqLogic->getConfiguration('createtime') . '</span></td></tr>';	
}
?>
	</tbody>
</table>
