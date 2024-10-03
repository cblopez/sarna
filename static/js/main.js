function ask_confirmation() {
    return new Promise(function (resolve, reject) {
        $("#dialog-confirm").dialog({
            resizable: false,
            height: 180,
            modal: true,
            buttons: {
                OK: function () {
                    $(this).dialog("close");
                    resolve();
                },
                Cancel: function () {
                    $(this).dialog("close");
                    reject();
                }
            }
        });
    });
}

/**
 * Tarlogic - Función para generar el vector CVSS 4.0
 */
function updateCVSS4Vector() {

    let form = document.getElementById('cvss4');

    let vector = 'CVSS:4.0';

    for (let i = 0; i < form.elements.length; i++) {
        let field = form.elements[i];
        if (field.tagName === 'SELECT') {
            vector += `/${field.name}:${field.value}`;
        }
    }

    document.getElementById('cvss4-vector').textContent = vector;
    updateCVSS4Score(vector);
    $('#cvss_v3_vector').val(vector);
}

/**
 * Tarlogic - Función para actualizar el vector CVSS 4.0 en la interfaz
 */
function updateCVSS4Score(vector) {
    let cvss4Vector = new Vector();
    cvss4Vector.updateMetricsFromVectorString(vector);
    let cvssInstance = new CVSS40(cvss4Vector);
    let cvssScore = cvssInstance.calculateScore()

    document.getElementById('cvss4-score').textContent = cvssScore;
    document.getElementById('cvss4-risk').textContent = cvssInstance.calculateSeverityRating(cvssScore);
    if (isNaN(cvssScore)) {
        $('#cvss_v3_score').val(0);
    } else {
        $('#cvss_v3_score').val(cvssScore);
    }
}

/**
 * Tarlogic - Función para rellenar automáticamente el form del vector CVSS 4.0 en base a un vector
 */

function populateCVSS4Form(vector) {
    
    let metrics = vector.replace('CVSS:4.0/', '').split('/');
    
    metrics.forEach(metric => {
        let [key, value] = metric.split(':');  
        
        let selectElement = document.querySelector(`select[name="${key}"]`);
        
        if (selectElement) {
            selectElement.value = value;
        }
    });

    updateCVSS4Vector()
    updateCVSS4Score(document.getElementById('cvss4-vector').textContent)
}


$(function () {
    marked.setOptions({sanitize: true});

    $('a.need-confirm').click(function (e) {
        var elem = $(this);
        var href = elem.attr('href');

        e.preventDefault();
        ask_confirmation().then(
            function () {
                let csrf_token = $('meta[name="csrf-token"]').attr('content');
                $('<form action="' + href + '" method="POST">')
                    .append($('<input type="hidden" name="csrf_token" value="' + csrf_token + '">'))
                    .appendTo($(document.body))
                    .submit();
            }
        );

    });

    let confirmed = false;
    $('button.need-confirm').click(function (e) {
        let elem = $(this);

        if (!confirmed) {
            e.preventDefault()
            ask_confirmation().then(
                function () {
                    confirmed = true;
                    elem.trigger('click')
                }
            );
        } else {
            confirmed = false;
        }
    });


    $(".clickable-row").click(function () {
        window.location = $(this).data("href");
    });

    $(".datepicker").datepicker({
        dateFormat: "yy-mm-dd"
    });

    $('#all_checked').click(function () {
        var is_checked = $(this).prop("checked");
        $('#table_data tr:has(td)').find('input[type="checkbox"]').prop('checked', is_checked);
    });

    $('#table_data tr:has(td)').find('input[type="checkbox"]').click(function () {
        var is_checked = $(this).prop("checked");
        var is_header_checked = $("#all_checked").prop("checked");
        if (is_checked == false && is_header_checked)
            $("#all_checked").prop('checked', is_checked);
        else {
            $('#table_data tr:has(td)').find('input[type="checkbox"]').each(function () {
                if ($(this).prop("checked") == false)
                    is_checked = false;
            });
            $("#all_checked").prop('checked', is_checked);
        }
    });
});