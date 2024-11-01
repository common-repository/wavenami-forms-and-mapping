jQuery(document).ready(function($) {

    var masking = {
        // User defined Values
        creditCardId: 'ccnum',
        maskedNumber: 'X',

        // object re: credit cards
        cardMasks: {
            3: {
                'card': 'amex',
                'placeholder': 'XXXX XXXXXX XXXXX',
                'pattern': '3\[47\]\\d \\d{6} \\d{5}',
                'regex': /^3[47]/,
                'regLength': 2
            },
            4: {
                'card': 'visa',
                'placeholder': 'XXXX XXXX XXXX XXXX',
                'pattern': '4\\d{3} \\d{4} \\d{4} \\d{4}',
                'regex': /^4/,
                'regLength': 1
            },
            5: {
                'card': 'mc',
                'placeholder': 'XXXX XXXX XXXX XXXX',
                'pattern': '5\[1-5\]\\d{2} \\d{4} \\d{4} \\d{4}',
                'regex': /^5[1-5]/,
                'regLength': 2
            },
            6: {
                'card': 'discover',
                'placeholder': 'XXXX XXXX XXXX XXXX',
                'pattern': '(6011 \\d\\d|6221 2\[6-9\]|6221 3\\d|622\[2-8\] \\d\\d|6229 \[01\]\\d|6229 2\[0-5\]|6226 4\[4-9\]|65\\d\\d \\d\\d)\\d{2} \\d{4} \\d{4}',
                'regex': /^(6011|6221 2[6-9]|6221 3|622[2-8]|6229 [01]|6229 2[0-5]|6226 4[4-9]|65)/,
                'regLength': 7
            }
        },

        init: function() {
            masking.createShell(document.getElementById(masking.creditCardId));
            masking.activateMasking(document.getElementById(masking.creditCardId));
        },

        // replaces each masked input with a shall containing the input and it's mask.
        // this should be credit card render in react
        createShell: function(input) {
            var text = '',

                // https://stackoverflow.com/questions/12625717/check-if-attributeid-exists-in-jquery
                // https://stackoverflow.com/questions/12161132/is-there-a-way-that-i-can-check-if-a-data-attribute-exists
                placeholder = input.getAttribute('placeholder');

            input.setAttribute('data-placeholder', placeholder);
            input.setAttribute('data-original-placeholder', placeholder);
            input.removeAttribute('placeholder');

            text = '<span class="shell">' +
                '<span aria-hidden="true" id="' + input.id +
                'Mask"><i></i>' + placeholder + '</span>' +
                input.outerHTML +
                '</span>';

            input.outerHTML = text;
        },

        setValueOfMask: function(value, placeholder) {
            return "<i>" + value + "</i>" + placeholder.substr(value.length);
        },

        // add event listeners. only did IE9+. Do we need attach Event?
        activateMasking: function(input) {
            input.addEventListener('keyup', function(e) {
                masking.handleValueChange(e);
            }, false);
            input.addEventListener('blur', function(e) {
                masking.handleBlur(e);
            }, false);
            input.addEventListener('focus', function(e) {
                masking.handleFocus(e);
            }, false);
        },

        handleValueChange: function(e) {
            var id = e.target.getAttribute('id'),
                currentMaskValue = document.querySelector('#' + id + 'Mask i'),
                currentInputValue = e.target.value = e.target.value.replace(/\D/g, "");

            // if there is no correct mask or if value hasn't changed, move on
            if (!currentMaskValue || currentInputValue == currentMaskValue.innerHTML) {
                return;
            }

            // If value is empty, not a number or out of range, remove any current cc type selection
            if (!currentInputValue || currentInputValue[0] < 3 || currentInputValue[0] > 6) {
                e.target.value = '';
                masking.returnToDefault(e);
                return;
            }

            // everything is right in the universe
            masking.setCreditCardType(e, currentInputValue[0]);

        },

        setCreditCardType: function(e, firstDigit) {
            var cc = masking.cardMasks[firstDigit],
                mask = document.getElementById(e.target.id + 'Mask');

            // alert(wavenami.pluginsUrl);
            // https://forms.wavenami.net/wp-content/plugins
            var icon_url = wavenami.pluginsUrl + '/wavenami-forms-and-mapping/front-end/assets/img/icons/' + cc.card + '.png';

            $("#ccnum").css("background-image", "url('" + icon_url + "')");
            // $("#cclabel").html( '<img src="' + icon_url + '">' );

            // set the credit card class
            // e.target.parentNode.parentNode.classList.add(cc.card);

            // set the credit card regex
            e.target.setAttribute('pattern', cc.pattern);

            // set the credit card pattern
            e.target.setAttribute('data-placeholder', cc.placeholder);

            // handle the current value
            e.target.value = masking.handleCurrentValue(e);

            // set the inputmask
            mask.innerHTML = masking.setValueOfMask(e.target.value, cc.placeholder);
        },

        returnToDefault: function(e) {
            console.log('return to default');
            var input = e.target,
                placeholder = input.getAttribute('data-original-placeholder');

            // set original placeholder
            input.setAttribute('data-placeholder', placeholder);
            document.getElementById(e.target.id + 'Mask').innerHTML = "<i></i>" + placeholder;

            // remove possible credit card classes
            input.parentNode.parentNode.classList.remove('error');
            for (var i = 3; i <= 6; i++) {
                e.target.parentNode.parentNode.classList.remove(masking.cardMasks[i].card);
            }

            // make sure value is empty
            input.value = '';
        },

        handleFocus: function(e) {
            var parentLI = e.target.parentNode.parentNode;
            parentLI.classList.add('focus');
        },

        handleBlur: function(e) {
            var parentLI = e.target.parentNode.parentNode,
                currValue = e.target.value,
                pattern, mod10, mod11 = true;

            // if value is empty, remove label parent class
            if (currValue.length == 0) {
                parentLI.classList.remove('focus');
            } else {
                pattern = new RegExp(e.target.getAttribute('pattern'));
                if (mod11 && currValue.replace(/\D/g, '').length == 16) {
                    console.log(masking.testMod11(currValue));
                }
                if (currValue.match(pattern) && masking.testMod10(currValue)) {
                    parentLI.classList.remove('error');
                } else {
                    parentLI.classList.add('error');
                }
            }
        },

        testMod10: function(value) {
            var strippedValue = value.replace(/\D/g, ''), // numbers only
                len = strippedValue.length, // 15 or amex, all others 16
                digit = strippedValue[len - 1], // tester digit
                i, myCheck,
                total = 0,
                temp;
            for (i = 2; i <= len; i++) {
                if (i % 2 == 0) {
                    temp = strippedValue[len - i] * 2;
                    if (temp >= 10) {
                        total += 1 + (temp % 10);
                    } else {
                        total += temp * 1;
                    }
                } else {
                    total += strippedValue[len - i] * 1;
                }
            }
            myCheck = (10 - (total % 10)) % 10;
            return ((myCheck + 1) % 10) == digit;
        },

        testMod11: function(value) {
            var strippedValue = value.replace(/\D/g, ''), // numbers only
                len = strippedValue.length, // usually 16
                digit = strippedValue[len - 1], // tester digit
                testDigits = strippedValue.substr(0, len - 1), // 15 or 12 digits
                i, myCheck,
                total = 0,
                temp;

            for (i = len - 1; i > 0;) {
                temp = Number(testDigits[--i]);
                if (i % 2 == 0) {
                    temp *= 2;
                }

                if (temp > 9) {
                    temp -= 9;
                }

                total += temp;
                console.log(total + " : " + temp);
            }
            console.log("Total: " + total);

            /*
               if card number is 16 digit, then fetch first 15 digits (card15) and last digit is check-digit
               else if card number is 13 digit, then fetch first 12 digits (card12) and last digit is check-digit
               as we don't have 13 digit card numbers, we're only doing 16 test.*/


            myCheck = (10 - (total % 10)) % 10;
            myCheck = (myCheck + 1) % 10;
            console.log("MyCheck: " + myCheck);
            var PAN = '' + testDigits + myCheck;
            console.log("Passed PAN {}" + strippedValue);
            console.log("Calculated PAN {}" + PAN);
            if (myCheck == digit && PAN == strippedValue) {
                return true;
            } else {
                return false;
            }
        },

        // tests whether there is an error in the credit card number at a specifi
        testRegExProgression: function(e, value) {
            var cc = masking.cardMasks[value[0]];
            if (value.length >= cc.regLength) {
                if (!cc.regex.test(value) && !e.target.parentNode.parentNode.classList.contains('error')) {
                    // show error message instead
                    e.target.parentNode.parentNode.classList.add('error');
                    masking.errorOnKeyEntry('You have an error in your credit card number', e);
                }
            } else {
                // remove error notfications if they deleted the excess characters
                e.target.parentNode.parentNode.classList.remove('error');
            }

        },

        handleCurrentValue: function(e) {
            var placeholder = e.target.getAttribute('data-placeholder'),
                value = e.target.value,
                l = placeholder.length,
                newValue = '',
                i, j, isInt, strippedValue;

            // strip special characters
            strippedValue = value.replace(/\D/g, "");

            for (i = 0, j = 0; i < l; i++) {
                var x =
                    isInt = !isNaN(parseInt(strippedValue[j]));
                matchesNumber = masking.maskedNumber.indexOf(placeholder[i]) >= 0;

                if (matchesNumber && isInt) {
                    newValue += strippedValue[j++];
                } else if (!isInt && matchesNumber) {
                    // masking.errorOnKeyEntry(); // write your own error handling function
                    return newValue;
                } else {
                    newValue += placeholder[i];
                }
                // break if no characters left and the pattern is non-special character
                if (strippedValue[j] == undefined) {
                    break;
                }
            }
            masking.testRegExProgression(e, newValue);

            return newValue;
        },

        errorOnKeyEntry: function(message, e) {
            console.log(message);
        }
    }

    if (jQuery("#ccnum").length) {
        masking.init();
    }

    // var foo = document.getElementById('cc')
});