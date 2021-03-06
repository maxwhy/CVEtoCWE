
fs = require('fs');
var parser = require('xml2json');  
var XMLHttpRequest = require('xhr2');
var json = require('../1000.json');

let CVE_list = [];
let CWE_list = [];
let count=0;
let rows=0;
let cveNumber=0;
var finalCAPEC = [''];
var finalCWE = [''];

function save(OVALpath, {reportname}){

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
        count++;
        httpGetAsync(url, printResponse, CVE_ID);
    }

    function httpGetAsync(theUrl, printResponse, CVE_ID){ 
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.onreadystatechange = function() { 
            if (xmlHttp.readyState == 4){
                if (xmlHttp.status === 200){
                        var json_cwe = JSON.parse(xmlHttp.responseText);
                        printResponse(json_cwe, CVE_ID, 0);
                }else{
                    printResponse(json_cwe, CVE_ID, 1);
                    console.log("Warning: " + CVE_ID + " returned "+ xmlHttp.status + " ("+ xmlHttp.statusText+ ")");
                }
            }
        }
        xmlHttp.open("GET", theUrl, true); // true for asynchronous 
        xmlHttp.timeout = 2000;
        xmlHttp.send(null);
        xmlHttp.ontimeout = function (e) {
            printResponse(' ', CVE_ID, 1);
            console.log("Warning: " + CVE_ID + " did not return ");
        }
    }

    function printResponse(text, CVE_ID, flag){
        if(flag == 1){
            if(!CVE_list.includes(CVE_ID)){
                cveNumber++;
            }
        }else{
            if(text.result.CVE_Items[0].cve.problemtype.problemtype_data[0].description[0]?.value != undefined){
                CVE_list.push(CVE_ID);
                CWE_list.push(text.result.CVE_Items[0].cve.problemtype.problemtype_data[0].description[0].value);
                cveNumber++;
                rows++;
            }
        }
        if(cveNumber==count){
            generateHTMLfile(CVE_list, CWE_list);
        } 
    }

    function generateHTMLfile(CVE_list, CWE_list){
        var fileName = '';
        if(reportname){
            fileName += reportname;
        }else{
            fileName = 'report.html'
        }
        var stream = fs.createWriteStream(fileName);
        stream.once('open', function(fd) {
            var html = buildHtml(CVE_list, CWE_list);
            stream.end(html);
        });
        console.log("Report saved as " + fileName + " (" + rows + " entries)");
    }

    function buildHtml(CVE_list, CWE_list){
        for(i=0;i<405;i++){
            id = json[i]['\'ID']
            string = json[i].CWE;
            array = string.split("::");
            n = Object.keys(array).length;
            for(j=1;j<n-1;j++){
                finalCAPEC.push(id);
                finalCWE.push(array[j]);
            }
        }

        var header = '';
        var body = '';
        var URL_CWE_ID = '';
        //concatenate header
        header += '<style>table, th, td {border: 1px solid black; border-collapse: collapse; padding: 5px; text-align: center;}</style>';
        //concatenate Body
        body += '<h1>Report</h1><table style="width:75%"><tr><th>Vulnerabilities</th><th>Weaknessess</th><th>Attack Pattern</th></tr>';
        for(j=0; j<rows; j++){
            body += '<tr><td>' + CVE_list[j] + '</td><td>';
            URL_CWE_ID = CWE_list[j].substring(4);
            if(URL_CWE_ID != 'CWE-Other' && URL_CWE_ID != 'CWE-noinfo'){
                body += '<a href="https://cwe.mitre.org/data/definitions/' + URL_CWE_ID + '" target="_blank">';
                body += CWE_list[j] + '</a></td><td>';
                for(k=0;k<1148;k++){
                    if(finalCWE[k] == URL_CWE_ID){
                        body += '<a href="https://capec.mitre.org/data/definitions/' + finalCAPEC[k] + '" target="_blank">';
                        body += finalCAPEC[k] + '</a> '
                    }
                }
                body += '</td></tr>';
            }else{
                body += CWE_list[j] + '</td><td></td></tr>';
            }
        }
      
        return '<!DOCTYPE html>' + '<html><head>' + header + '</head><body>' + body + '</body></html>';
    }

}

module.exports = save
