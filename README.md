[comment]: # "Auto-generated SOAR connector documentation"
# Anubis

Publisher: Phantom Cyber  
Connector Version: 1\.2\.22  
Product Vendor: Anubis  
Product Name: Anubis  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 1\.2\.236  

This app supports executing investigative actions like 'detonate file' and 'detonate url' to analyze executables and URLs on the online Anubis Malware Analysis tool\.

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Anubis asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**timeout** |  required  | numeric | Timeout \(seconds\)

### Supported Actions  
[detonate file](#action-detonate-file) - Run the file in the Anubis sandbox and retrieve the analysis results\.  
[get report](#action-get-report) - Query for results of an already completed task in Anubis\.  
[detonate url](#action-detonate-url) - Load a URL in the Anubis sandbox and retrieve the analysis results\.  
[test connectivity](#action-test-connectivity) - This action connects to the server to verify the connection\.  

## action: 'detonate file'
Run the file in the Anubis sandbox and retrieve the analysis results\.

Type: **investigate**  
Read only: **True**

This action requires the input file to be present in the vault and therefore takes the vault id as the input parameter

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault ID of file to detonate | string |  `pe file` 
**file\_name** |  optional  | Filename to use | string |  `file name` 
**force\_analysis** |  optional  | Force re\-run of sample | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary\.id | string |  `anubis task id` 
action\_result\.summary\.results\_url | string | 
action\_result\.summary\.target | string |  `file name`   

## action: 'get report'
Query for results of an already completed task in Anubis\.

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Task ID to get the results of | string |  `anubis task id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary\.id | string |  `anubis task id` 
action\_result\.summary\.results\_url | string | 
action\_result\.summary\.target | string |  `file name`   

## action: 'detonate url'
Load a URL in the Anubis sandbox and retrieve the analysis results\.

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to detonate | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.summary\.id | string |  `anubis task id` 
action\_result\.summary\.results\_url | string | 
action\_result\.summary\.target | string |  `file name`   

## action: 'test connectivity'
This action connects to the server to verify the connection\.

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output