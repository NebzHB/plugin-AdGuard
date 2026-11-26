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

require_once dirname(__FILE__) . '/../../../core/php/core.inc.php';

function AdGuard_update() {
	// La beta a brièvement confié les confirmations au core (actionConfirm). Les widgets posent leurs propres questions :
	// on retire actionConfirm une seule fois de ces commandes, sinon l'action serait confirmée deux fois.
	if (config::byKey('actionConfirmRemoved', 'AdGuard', 0) != 1) {
		$confirmed = ['internet_block', 'filtering_disable', 'parental_disable', 'services_block', 'services_unblock', 'cache_clear', 'filters_refresh', 'reset_stats', 'UpdateAdGuard',
			'client_internet_block', 'client_filtering_disable', 'client_parental_disable', 'client_services_block', 'client_services_unblock'];
		foreach (eqLogic::byType('AdGuard') as $AdGuard) {
			foreach ($confirmed as $logicalId) {
				$cmd = $AdGuard->getCmd('action', $logicalId);
				if (is_object($cmd) && $cmd->getConfiguration('actionConfirm', 0) == 1) {
					$cmd->setConfiguration('actionConfirm', 0);
					$cmd->save();
				}
			}
		}
		config::save('actionConfirmRemoved', 1, 'AdGuard');
	}
	foreach (eqLogic::byType('AdGuard') as $AdGuard) {
		/*if($AdGuard->getConfiguration('type','') == 'AdGuardGlobal')*/ $AdGuard->save();
	}
}

?>
