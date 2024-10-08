<?php
if (!isConnect('admin')) {
  throw new Exception('{{401 - Accès non autorisé}}');
}

sendVarToJS('eqType', 'AdGuard');
$eqLogics = eqLogic::byType('AdGuard');
?>
<div class="row row-overflow">
  <div class="col-xs-12 eqLogicThumbnailDisplay">
    <legend><i class="fas fa-cog"></i>  {{Gestion}}</legend>
    <div class="eqLogicThumbnailContainer">
      <div class="cursor eqLogicAction logoPrimary" data-action="add">
        <i class="fas fa-plus-circle"></i>
        <br>
        <span>{{Ajouter}}</span>
      </div>
      <div class="cursor eqLogicAction logoSecondary" data-action="gotoPluginConf">
        <i class="fas fa-wrench"></i>
        <br>
        <span>{{Configuration}}</span>
      </div>
      <div class="cursor logoSecondary" id="bt_healthAdGuard">
        <i class="fas fa-medkit"></i>
        <br>
        <span>{{Santé}}</span>
      </div>
	<?php
		$jeedomVersion=jeedom::version() ?? '0';
		$displayInfo=version_compare($jeedomVersion, '4.4.0', '>=');
		if($displayInfo){
			echo "<div class=\"cursor eqLogicAction warning\" data-action=\"createCommunityPost\" title=\"{{Ouvrir une demande d'aide sur le forum communautaire}}\">";
			echo '<i class="fas fa-ambulance"></i><br>';
			echo '<span>{{Community}}</span>';
			echo '</div>';
		}
	?>
    </div>
    <legend><i class="fas fa-table"></i>  {{Mes serveurs AdGuard et clients}}</legend>
	<?php
				$i=1;
				foreach ($eqLogics as $eqLogicAdGuard) :
					if($eqLogicAdGuard->getConfiguration('type','') != 'AdGuardGlobal') continue;
		?>
					<legend> <?php echo $eqLogicAdGuard->getHumanName(true)?></legend>
					<div class="input-group" style="margin-bottom:5px;">
						<input class="form-control roundedLeft searchBox" placeholder="{{Rechercher}}" id="in_searchEqlogic<?php echo $i?>" />
						<div class="input-group-btn">
							<a id="bt_resetEqlogicSearch<?php echo $i?>" class="btn roundedRight" style="width:30px"><i class="fas fa-times"></i></a>
						</div>
					</div>
					<div class="panel">
						<div class="panel-body">
							<div class="eqLogicThumbnailContainer">
							  <?php
								foreach ($eqLogics as $eqLogic) {
									if($eqLogic->getConfiguration('type','') != 'AdGuardGlobal') continue;
									if($eqLogic->getId() != $eqLogicAdGuard->getId()) continue;
									$opacity = ($eqLogic->getIsEnable()) ? '' : ' disableCard';
									$img=$eqLogic->getImage();
									echo '<div class="eqLogicDisplayCard cursor cont'.$i.$opacity.'" data-eqLogic_id="' . $eqLogic->getId() . '">';
									echo '<img class="lazy" src="'.$img.'" style="min-height:75px !important;" />';	
									echo "<br />";
									echo '<span class="name">' . $eqLogic->getHumanName(true, true) . '</span>';
									echo '</div>';
								}
								foreach ($eqLogics as $eqLogic) {
									if($eqLogic->getConfiguration('type','') != 'Client') continue;
									if($eqLogic->getConfiguration('server','') != $eqLogicAdGuard->getId()) continue;
									$opacity = ($eqLogic->getIsEnable()) ? '' : ' disableCard';
									$img=$eqLogic->getImage();
									echo '<div class="eqLogicDisplayCard cursor cont'.$i.$opacity.'" data-eqLogic_id="' . $eqLogic->getId() . '">';
									echo '<img class="lazy" src="'.$img.'" style="min-height:75px !important;" />';	
									echo "<br />";
									echo '<span class="name">' . $eqLogic->getHumanName(true, true) . '</span>';
									echo '</div>';
								}
							  ?>
							</div>
						</div>
					</div>
	<?php
				$i++;
				endforeach;

		?>
  </div>
  <div class="col-xs-12 eqLogic" style="display: none;">
    <div class="input-group pull-right" style="display:inline-flex">
      <span class="input-group-btn">
        <a class="btn btn-sm btn-default eqLogicAction roundedLeft" data-action="configure"><i class="fas fa-cogs"></i> {{Configuration avancée}}
        </a><a class="btn btn-sm btn-success eqLogicAction" data-action="save"><i class="fas fa-check-circle"></i> {{Sauvegarder}}
        </a><a class="btn btn-sm btn-danger eqLogicAction roundedRight" data-action="remove"><i class="fas fa-minus-circle"></i> {{Supprimer}}</a>
      </span>
    </div>

  <ul class="nav nav-tabs" role="tablist">
    <li role="presentation"><a class="eqLogicAction cursor" aria-controls="home" role="tab" data-action="returnToThumbnailDisplay"><i class="fas fa-arrow-circle-left"></i></a></li>
    <li role="presentation" class="active"><a href="#eqlogictab" aria-controls="home" role="tab" data-toggle="tab"><i class="fas fa-tachometer-alt"></i> {{Equipement}}</a></li>
    <li role="presentation"><a href="#commandtab" aria-controls="profile" role="tab" data-toggle="tab"><i class="fas fa-list-alt"></i> {{Commandes}}</a></li>
  </ul>

  <div class="tab-content" style="height:calc(100% - 50px);overflow:auto;overflow-x: hidden;">
    <div id="eqlogictab" role="tabpanel" class="tab-pane active">
      <br>
      <div class="row">
        <div class="col-sm-9">
          <form class="form-horizontal">
            <fieldset>
              <div class="form-group">
                <label class="col-lg-3 control-label">{{Nom de l'équipement}}</label>
                <div class="col-lg-4">
                  <input type="text" class="eqLogicAttr form-control" data-l1key="id" style="display : none;" />
				  <span class="eqLogicAttr hidden" data-l1key="configuration" data-l2key="type"></span>
                  <input type="text" class="eqLogicAttr form-control" id="eqName" data-l1key="name" placeholder="{{Nom de l'équipement}}"/>
                </div>
              </div>
              <div class="form-group">
                <label class="col-lg-3 control-label" >{{Objet parent}}</label>
                <div class="col-lg-4">
                  <select id="sel_object" class="eqLogicAttr form-control" data-l1key="object_id">
                    <option value="">{{Aucun}}</option>
						<?php
						foreach ((jeeObject::buildTree(null, false)) as $object) {
							echo '<option value="' . $object->getId() . '">' . str_repeat('&nbsp;&nbsp;', $object->getConfiguration('parentNumber')) . $object->getName() . '</option>';
						}
						?>
                  </select>
                </div>
              </div>
              <div class="form-group">
                <label class="col-sm-3 control-label">{{Catégorie}}</label>
                <div class="col-sm-9">
                 <?php
                  foreach (jeedom::getConfiguration('eqLogic:category') as $key => $value) {
					  echo '<label class="checkbox-inline">';
					  echo '<input type="checkbox" class="eqLogicAttr" data-l1key="category" data-l2key="' . $key . '" />' . $value['name'];
					  echo '</label>';
                  }
                  ?>
                </div>
              </div>
              <div class="form-group">
                <label class="col-sm-3 control-label"></label>
                <div class="col-sm-9">
                  <label class="checkbox-inline"><input type="checkbox" class="eqLogicAttr" data-l1key="isEnable" checked/>{{Activer}}</label>
                  <label class="checkbox-inline"><input type="checkbox" class="eqLogicAttr" data-l1key="isVisible" checked/>{{Visible}}</label>
                </div>
              </div>
              <div class="form-group" id="ipDevice">
                <label class="col-sm-3 control-label help" data-help="{{Si vous avez modifié le port par défaut (80) vous pouvez ajouter votre port ici sous la forme ip:port. Sinon juste l'ip}}">{{Ip du serveur}}</label>
                <div class="col-sm-4">
		  <div class="input-group">
		    <select class="eqLogicAttr form-control roundedLeft" data-l1key="configuration" data-l2key="proto">
			<option value="http" selected>HTTP</option>
			<option value="https">HTTPS</option>
		    </select>
		    <span class="input-group-addon">://</span>
                    <input type="text" class="eqLogicAttr form-control roundedRight" data-l1key="configuration" data-l2key="ip" placeholder="{{Ip du serveur AdGuard}}"/>
		  </div>
		</div>
              </div>
              <div class="form-group" id="userDevice">
                <label class="col-sm-3 control-label">{{Utilisateur}}</label>
                <div class="col-sm-4">
                  <input type="text" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="user" placeholder="{{Utilisateur de votre serveur}}"/>
                </div>
              </div>
			  <div class="form-group" id="passDevice">
                <label class="col-sm-3 control-label">{{Mot de passe}}</label>
                <div class="col-sm-4">
                  <input type="password" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="password" placeholder="{{Mot de passe de votre utilisateur}}"/>
                </div>
              </div>
              <div class="form-group expertModeVisible" id="cronDevice">
                <label class="col-sm-3 control-label">{{Auto-actualisation (cron)}}</label>
                  <div class="col-sm-3">
                    <input type="text" class="eqLogicAttr form-control" data-l1key="configuration" data-l2key="autorefresh" placeholder="*/5 * * * *"/>
                  </div>
                  <div class="col-sm-1">
                    <i class="fas fa-question-circle cursor floatright" id="bt_cronGenerator"></i>
                  </div>
              </div>
            </fieldset>
          </form>
        </div>

        <!--<form class="form-horizontal col-sm-3">
          <fieldset>
            <div class="form-group">
              <img src="plugins/AdGuard/plugin_info/AdGuard_icon.png" style="height: 200px;" />
            </div>
          </fieldset>
        </form>-->
      </div>
    </div>
    <div role="tabpanel" class="tab-pane" id="commandtab">
      <legend><i class="fas fa-list-alt"></i>  {{Tableau de commandes}}</legend>
      <table id="table_cmd" class="table table-bordered table-condensed">
        <thead>
          <tr>
            <th>{{Nom}}</th><th>{{Valeurs}}</th><th>{{Action}}</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
  </div>
</div>

<?php
  include_file('desktop', 'AdGuard', 'js', 'AdGuard');
  include_file('core', 'plugin.template', 'js');
?>
