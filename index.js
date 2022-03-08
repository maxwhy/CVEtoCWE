#! /usr/bin/env node

const { program } = require('commander');
const show = require('./commands/show');
const save = require('./commands/save');

program
    .command('show <OVALpath>') 
    .description('Prints to terminal the list of CVE identifiers and their relative CWEs')
    .action(show) //The argument "OVALpath" is the passed to the function with that name

program
    .command('save <OVALpath>') 
    .description('Saves into an HTML file the list of CVE identifiers with their relative CWE and CAPEC entries')
    .option('--reportname <reportname>', 'The name of the file where the list is saved. If omitted, the default name is report.html')
    .action(save) 

program.parse()

