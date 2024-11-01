var wrapper = document.getElementById("signature-pad"),
    clearButton = wrapper.querySelector("[data-action=clear]"),
    savePNGButton = wrapper.querySelector("[data-action=save-png]"),
    saveSVGButton = wrapper.querySelector("[data-action=save-svg]"),
    canvas = wrapper.querySelector("canvas"),
    signaturePad;

// Adjust canvas coordinate space taking into account pixel ratio,
// to make it look crisp on mobile devices.
// This also causes canvas to be cleared.
function resizeCanvas() {
    // When zoomed out to less than 100%, for some very strange reason,
    // some browsers report devicePixelRatio as less than 1
    // and only part of the canvas is cleared then.
    var ratio =  Math.max(window.devicePixelRatio || 1, 1);
    canvas.width = canvas.offsetWidth * ratio;
    canvas.height = canvas.offsetHeight * ratio;
    canvas.getContext("2d").scale(ratio, ratio);
}

window.onresize = resizeCanvas;
resizeCanvas();

signaturePad = new SignaturePad(canvas);

clearButton.addEventListener("click", function (event) {
    signaturePad.clear();
});

saveSVGButton.addEventListener("click", function (event) {
    if (signaturePad.isEmpty()) {
        alert("Please provide signature first.");
    } else {
        // window.open(signaturePad.toDataURL('image/svg+xml'));
        var sig = {};
        sig.svg_xml = signaturePad.toDataURL('image/svg+xml');
        sig.svg = signaturePad.toDataURL('image/svg');
        console.log(sig);
        $.ajax({
            url: "/apply/signature",
            type: "POST",
            cache: false,
            dataType: "json",
            data: sig,
            success: function(data){
                console.log(data);
                alert(data);
                if(data == 'pass'){
                    //alert('success');
                    return true;
                    /*
                     swal({
                     title: points_written + " points saved",
                     text: " Your map have been saved! Click the Close button if you're finished to go back to Venue Maps.",
                     type: "success",
                     confirmButtonText: "Ok",
                     allowOutsideClick: true
                     });
                     */
                }else{
                    //alert('fail');
                    return false;
                    /*
                     swal({
                     title: "info",
                     text: "Your map could not be saved. If you continue to see this error, please contact support.",
                     type: "error",
                     confirmButtonText: "Ok",
                     allowOutsideClick: true
                     });
                     */
                }
            }
        });
    }
});
