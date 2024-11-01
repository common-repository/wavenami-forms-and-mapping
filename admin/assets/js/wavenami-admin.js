jQuery(document).ready(function($) {
	
	$('#add-new-group-wrap').insertAfter($('table:last-of-type'));
	
	$('.wavenami-add-group-button').click(function(){
		var data = {
			'action': 'wavenami_add_group',
			'groupName': $('input[name="wavenami_add_new_group"]').val(),
		};
		// We can also pass the url value separately from ajaxurl for front end AJAX implementations
		jQuery.post(ajax_object.ajax_url, data, function(response) {
			response = $.parseJSON(response);
			
			if (response['status'] == 'success') {
				$('input#refresh').trigger('click');
			} else {
				// probably give the user some feedback here about the group not being added.
				$('span.add-group-response').html('Something went wrong! Group not added!');
				
				// Then print out the full response in the console so we can figure out what's up
				console.log(response);
			}
		});
	});
	
	$('.wavenami-custom-fields').hover(function(){
		$('.wavenami-custom-content-cta').show().addClass('flipInX animated');
	});
	
	var showRecaptchaFields = function() {
		$('#wavenami-check-recaptcha').next('table').find('tr').show();
	}
	
	var hideRecaptchaFields = function() {
		$('#wavenami-check-recaptcha').next('table').find('tr:not(:first-child)').hide();
	}
	
	if ( $('#wavenami-check-recaptcha').hasClass('show-recaptcha-settings') )
		showRecaptchaFields();
	
	$('#wavenami_use_recaptcha').on('change', function(){
		if ( $('#wavenami_use_recaptcha:checked').length > 0 ) {
			showRecaptchaFields();
		} else {
			hideRecaptchaFields();
		}
	});
	
});