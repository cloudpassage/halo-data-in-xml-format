#Halo Data Connector

Version: *1.0*
<br />
Author: *Apurv Singh* - *apurva@cloudpassage.com*

The purpose of the Halo Data Connector is to retrieve Halo scan findings from a CloudPassage Halo account and import it into an external tool for processing. The Connector is a Ruby script that is designed to execute repeatedly, keeping the external tool up-to-date with the most recent scan findings, as time passes and new scans occur.

##Prerequisites

To get started, you must have the following privileges and software resources:

* An active CloudPassage Halo Professional subscription. If you don't have one, Register for CloudPassage to receive your credentials and further instructions by email.
* Access to your CloudPassage API key. Best practice is to create a new read-only key specifically for use with this script.
* Ruby 1.9 or later. You can download Ruby from here.
* The Data Connector script (haloDataInXMLFormat.rb) and its associated files:
    * halo-api-lib-2.3.0.gem
    * cacerts.pem (Required if running the connector on Windows)

These files can be downloaded from: __________

*Note*:  The connector script makes calls to the CloudPassage Halo API. While some of the APIs being called are available to all Halo subscribers at all levels (including Basic), others are available only to Halo users with a NetSec or Professional subscription


##How the Connector Works 

Each time the Connector runs, it by default retrieves all latest scan findings for all active servers from a single Halo account.

In case of Configurations scans, the script can also retrieve any events associated with the scans. You can specify how far back events are retrieved from by using the --starting=datetime command-line option.

Every subsequent time it runs, the Connector retrieves all events for configuration scans, for each server, that were created after the –starting= datetime. 

**Output formats.** The Event Connector converts Halo data to XML format before publishing it.

**Command line arguments.** In Ruby, you execute the Connector script with a command like this:

```
$ ./haloDataInXMLFormat.rb arguments
```


To view the set of supported command-line arguments, launch the script with the argument -? or -h to view the usage page. These are the arguments:

```-?``` Print the usage page.

```--auth=filename``` Full pathname to the file that holds the Halo API key info. 

```--starting=datetime``` Start retrieving scan findings from this (ISO-8601) date-time. Only valid with the –scan=sca-with-events option.

```--scan=scantype``` SCA or SVM scan data

```--output=filename``` Send the output to a file on the local file system.

*Note*: The default output format of this connector is XML, to standard output (terminal).

**Authentication to the Halo API.** Halo requires the Connector to pass both the key ID and secret key values for a valid Halo API key in order to obtain the scan data. You pass those values in a file named by default issues.auth, located in the same directory as haloDataInXMLFormat.rb and its associated script files. The format for the file is described in Section A.

Alternatively, you can pass those values in a different file by specifying the full path to the file in the --auth=filename option. 

**Output to a file.** Whenever it writes event data to a disk file, the Connector overwrites the existing data with new data.

**Platform support.** The Event Connector runs on both Linux and Windows operating systems.



###A. Retrieve and Save your CloudPassage API Key

The Connector retrieves scan findings from your CloudPassage Halo account by making calls to the CloudPassage API. The API requires the script to authenticate itself during every session; therefore, you need to make your CloudPassage API Key available to the script. 

If you do create an API key, we recommend that, as a best practice, you create a read-only key. A read-only key is all that you need to be able to retrieve Halo event data.

Copy the ID and the secret into a text file so that it contains just one line, with the key ID and the secret separated by a vertical bar ("|"):
```
your_key_id|your_secret_key
```

Save the file as issues.auth (or any other name, if you will be using the --auth command option). You will need this authentication file to run the Connector (in Section B).

###B. Test the Connector Standalone

We recommend that you execute the Connector script standalone first, to get familiar with the different input switches and output formats it supports. 

Place all of the script-related files in the same directory. That is:
* haloDataInXMLFormat.rb
* halo-apil-lib-2.3.0
* cacerts.pem (If running the script on a Windows machine)
* issues.auth (unless you will use the --auth command option, in which case the authentication file can be anywhere.)

Launch the Connector from that directory, with a command like this:
```
$ ./haloDataInXMLFormat –scan=sca –output=testScanData
```

Since the arguments are for SCA scans, you should soon see XML-formatted scan issues being written to the output file named testScanData.

Run the script a few more times, experimenting with arguments to send output to the standard output, or to produce other scan outputs.
