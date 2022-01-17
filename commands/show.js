
fs = require('fs');
var parser = require('xml2json');  
var XMLHttpRequest = require('xhr2');

function show(OVALpath){
    fs.readFile( OVALpath, function(err, data) {
        if(err){
            console.log("Error: cannot read input file");
        }else{
            try{
                const json = JSON.parse(parser.toJson(data));
                var result_def = json.oval_results.results.system.definitions.definition;
                var source_def = json.oval_results.oval_definitions.definitions.definition;
                if(!result_def || !source_def){
                    console.log("Input file doesn't contain any OVAL Definition");
                }else{
                    result_def.forEach((e, i) => {
                        if(source_def[i].class == "patch"){
                            if(e.result == "true"){
                                findAssociatedCVE(i, source_def);
                            }
                        }
                    });
                }
            }catch(e){
                console.log("Error: input file cannot be converted (Syntax error)");
            }
        }
    });

    function findAssociatedCVE(index, source_def){
        var ref = source_def[index].metadata.reference;
        Array.from(ref).forEach(e => {
            if(e.source == "CVE") {
                CVEtoCWE(e.ref_id);
            }
        });
    }

    function CVEtoCWE(CVE_ID){
        var url = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + CVE_ID;
        //setTimeout(httpGetAsync(url, printResponse, CVE_ID), 100);
        httpGetAsync(url, printResponse, CVE_ID);
    }

    function httpGetAsync(theUrl, printResponse, CVE_ID){
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.onreadystatechange = function() { 
            if (xmlHttp.readyState == 4){
                if (xmlHttp.status === 200){
                    try{
                        var json_cwe = JSON.parse(xmlHttp.responseText);
                        printResponse(json_cwe, CVE_ID);
                    }catch(e){
                        console.log("Error: HTTP response cannot be converted (Syntax error). URL: " + theUrl);
                    }
                }else{
                    console.log("Warning: " + CVE_ID + " returned "+ xmlHttp.status + " ("+ xmlHttp.statusText+ ")");
                }
            }
        }
        xmlHttp.open("GET", theUrl, true); // true for asynchronous 
        xmlHttp.send(null);
    }

    function printResponse(text, CVE_ID){
        console.log(CVE_ID + ": " + text.result.CVE_Items[0].cve.problemtype.problemtype_data[0].description[0].value);
    }

}

module.exports = show