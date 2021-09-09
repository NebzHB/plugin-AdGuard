
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

 $('#bt_healthAdGuard').on('click', function () {
    $('#md_modal').dialog({title: "{{Santé AdGuard}}"});
    $('#md_modal').load('index.php?v=d&plugin=AdGuard&modal=health').dialog('open');
});
 
 $("#table_cmd").sortable({axis: "y", cursor: "move", items: ".cmd", placeholder: "ui-state-highlight", tolerance: "intersect", forcePlaceholderSize: true});
 
  $('#bt_cronGenerator').on('click',function(){
    jeedom.getCronSelectModal({},function (result) {
        $('.eqLogicAttr[data-l1key=configuration][data-l2key=autorefresh]').value(result.value);
    });
});
 
function addCmdToTable(_cmd) {
    if (!isset(_cmd)) {
        var _cmd = {configuration: {}};
    }
    var tr = '<tr class="cmd" data-cmd_id="' + init(_cmd.id) + '">';
    tr += '<td>';
    tr += '<input class="cmdAttr form-control input-sm" data-l1key="id" style="display : none;">';
    tr += '<div class="row">';
	tr += '<div class="col-sm-6">';
	tr += '<input class="cmdAttr form-control input-sm" data-l1key="name">';
	tr += '</div>';
	tr += '<div class="col-sm-6">';
	tr += '<a class="cmdAction btn btn-default btn-sm" data-l1key="chooseIcon"><i class="fa fa-flag"></i> Icone</a>';
	tr += '<span class="cmdAttr" data-l1key="display" data-l2key="icon" style="margin-left : 10px;"></span>';
	tr += '</div>';
	tr += '</div>';
	tr += '<td>';
    tr += '<span class="cmdAttr" data-l1key="configuration" data-l2key="parameters"></span>';
    tr += '</td>'; 
	tr += '<td>';
	if (_cmd.logicalId != 'refresh'){
    tr += '<span><label class="checkbox-inline"><input type="checkbox" class="cmdAttr checkbox-inline" data-l1key="isVisible" checked/>{{Afficher}}</label></span> ';
    }
	if (_cmd.subType == "numeric") {
        tr += '<span><label class="checkbox-inline"><input type="checkbox" class="cmdAttr checkbox-inline" data-l1key="isHistorized" checked/>{{Historiser}}</label></span> ';
    }
	if (_cmd.subType == "binary") {
        tr += '<span><label class="checkbox-inline"><input type="checkbox" class="cmdAttr checkbox-inline" data-l1key="isHistorized" checked/>{{Historiser}}</label></span> ';
    }
	tr += '</td>';
	tr += '<td>';
    tr += '<input class="cmdAttr form-control input-sm" data-l1key="type" style="display : none;">';
    tr += '<input class="cmdAttr form-control input-sm" data-l1key="subType" style="display : none;">';
    if (is_numeric(_cmd.id)) {
        tr += '<a class="btn btn-default btn-xs cmdAction expertModeVisible" data-action="configure"><i class="fa fa-cogs"></i></a> ';
        tr += '<a class="btn btn-default btn-xs cmdAction" data-action="test"><i class="fa fa-rss"></i> {{Tester}}</a>';
    }
	tr += '<i class="fa fa-minus-circle pull-right cmdAction cursor" data-action="remove"></i></td>';
    tr += '</tr>';
    $('#table_cmd tbody').append(tr);
    $('#table_cmd tbody tr:last').setValues(_cmd, '.cmdAttr');
    jeedom.cmd.changeType($('#table_cmd tbody tr:last'), init(_cmd.subType));
}

$('body').on('AdGuard::includeDevice', function(_event,_options) {
    console.log("includeDevice received");
    if (modifyWithoutSave) {
        $('#div_inclusionAlert').showAlert({message: '{{Un client vient d\'être ajouté. Réactualisation de la page}}', level: 'warning'});
    } else {
            window.location.reload();        
    }
});

$('.eqLogicAttr[data-l1key=configuration][data-l2key=type]').on('change',function(a){
	var type = $(this).text();
	if(type){
		if(type == "Client") {
			$('#ipDevice').hide();
			$('#userDevice').hide();
			$('#passDevice').hide();
			$('#cronDevice').hide();
			
			$('#eqName').addClass('disabled');
			$('#eqName').attr('title', '{{Doit être modifié dans AdGuard Home}}');
			//add save roundedRight
			setTimeout(function(){
				console.log($('.eqLogicAttr[data-l1key=isEnable]').is(':checked'));
				if($('.eqLogicAttr[data-l1key=isEnable]').is(':checked')) {
					$('a[data-action=remove]').hide();
					$('a[data-action=save]').addClass('roundedRight');
				} else {
					$('a[data-action=remove]').show();
					$('a[data-action=save]').removeClass('roundedRight');
				}
			},100);
		}
		else {
			$('#ipDevice').show();
			$('#userDevice').show();
			$('#passDevice').show();
			$('#cronDevice').show();
			$('a[data-action=remove]').show();
			$('a[data-action=save]').removeClass('roundedRight');
			$('#eqName').removeClass('disabled');
			$('#eqName').attr('title','{{Nom de l\'équipement}}');
			//remove save roundedRight
		}
	}
});


for(var i=1;i<($('.searchBox').length+1);i++) {
	if($('#in_searchEqlogic'+i).length) {
		$('#in_searchEqlogic'+i).off('keyup').keyup(function() {
			var n = this.id.replace('in_searchEqlogic','');
			var search = $(this).value().toLowerCase();
			search = search.normalize('NFD').replace(/[\u0300-\u036f]/g, "");
			if(search == ''){
				$('.eqLogicDisplayCard.cont'+n).show();
				$('.eqLogicThumbnailContainer.cont'+n).packery();
				return;
			}
			$('.eqLogicDisplayCard.cont'+n).hide();
			$('.eqLogicDisplayCard.cont'+n+' .name').each(function(){
				var text = $(this).text().toLowerCase();
				text = text.normalize('NFD').replace(/[\u0300-\u036f]/g, "");
				if(text.indexOf(search) >= 0){
					$(this).closest('.eqLogicDisplayCard.cont'+n).show();
				}
			});
			$('.eqLogicThumbnailContainer.cont'+n).packery();
		});
		$('#bt_resetEqlogicSearch'+i).on('click', function() {
			var n = this.id.replace('bt_resetEqlogicSearch','');
			$('#in_searchEqlogic'+n).val('');
			$('#in_searchEqlogic'+n).keyup();
		});
	}
}
