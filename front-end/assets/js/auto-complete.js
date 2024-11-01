jQuery(document).ready(function($){

    var autocomplete_options = {
        url: myScript.pluginsUrl + '/wavenami-forms-and-mapping/front-end/assets/autocomplete/countries.json',

        dataType: "json",
        xmlElementName: "country",
        getValue: "name",

        list: {
            match: {
                enabled: true
            },
            onSelectItemEvent: function() {
                var alpha2 = $("#country-json").getSelectedItemData().alpha_2;
                $("#country-alpha-2").val(alpha2).trigger("change");

                var alpha3 = $("#country-json").getSelectedItemData().alpha_3;
                $("#country-alpha-3").val(alpha3).trigger("change");
            }
        }
    };

    $("#country-json").easyAutocomplete(autocomplete_options);

});