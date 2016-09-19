#!/usr/bin/python
import sqlite3
import sys
from optparse import OptionParser

# Dionaea Query Script v0.1
# By Chris Campbell
#
# https://www.twitter.com/t0x0_nz
# https://bytefog.blogspot.com
#
# Credit goes to Andrew Waite (www.infosanity.co.uk) for the original 2009 script.

def execute_query(query):
	conn = sqlite3.connect('/opt/dionaea/var/dionaea/dionaea.sqlite')
	c = conn.cursor()
	c.execute(query)
	
	for row in c:
		print(row)
	
	conn.close()


def run_query(query_num, query_port=None):
    if query_num == '1':
        queryDesc = "List of attacked ports."
        querySQL = 'SELECT local_port AS port, COUNT(local_port) AS hitcount FROM connections WHERE connection_type = "accept" GROUP BY local_port HAVING COUNT(local_port) > 10'
        queryColumns = ("Local Port", "Hits")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    #Attacks over a day
    elif query_num == '2':
        queryDesc = "Attacks over a day."
        querySQL = 'SELECT ROUND((connection_timestamp%(3600*24))/3600) AS hour, COUNT(*) FROM connections WHERE connection_parent IS NULL GROUP BY ROUND((connection_timestamp%(3600*24))/3600)'
        queryColumns = ("Hour", "Hits")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    #Popular Malware Downloads
    elif query_num == '3':
        queryDesc = "Popular malware downloads."
        querySQL = 'SELECT download_md5_hash, COUNT(download_md5_hash) FROM downloads GROUP BY download_md5_hash ORDER BY COUNT(download_md5_hash) DESC LIMIT 10'
        queryColumns = ("MD5 Hash", "Submission Count")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)
			
    #Busy Attackers
    elif query_num == '4':
        queryDesc = "Busy attackers."
        querySQL = 'SELECT remote_host, COUNT(remote_host) FROM connections WHERE connection_type = "accept" GROUP BY remote_host ORDER BY COUNT(remote_host) DESC LIMIT 10'
        queryColumns = ("Remote Host", "Hits")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    #Popular Download locations
    elif query_num == '5':
        queryDesc = "Popular download locations."
        querySQL = 'SELECT COUNT(*),download_url FROM downloads GROUP BY download_url ORDER BY COUNT(*) DESC LIMIT 20'
        queryColumns = ("Hits", "Download URL")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    #Connections in last 24 hours
    elif query_num == '6' and query_port != None:
        print "Port: "
        query_port = raw_input()
        queryDesc = "Connections in last 24hrs."
        querySQL = 'SELECT datetime(connection_timestamp, "unixepoch", "localtime"), remote_host, local_port, connection_transport, connection_protocol FROM connections WHERE connection_timestamp > strftime("%s", "now", "-1 day") AND local_port = "{}"'.format(query_port)
        queryColumns = ("Time", "Remote IP", "Local Port", "Transport", "Protocol")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)
		
    #Activity for 
	
    else:
        print 'Invalid option(s). Valid options are:'
        show_options()


def show_options():
    print "\t1:\tPort attack frequency."
    print "\t2:\tAttacks over a day."
    print "\t3:\tPopular malware downloads."
    print "\t4:\tBusy attackers."
    print "\t5:\tPopular download locations."
    print "\t6:\tConnections in last 24hrs (requires explicit port definition)."


def main():
    parser = OptionParser(usage="%prog [-f] [-q]", version="%prog 0.1")
    parser.add_option("-q", "--query", dest="query", help="Number of the query to run.")
    parser.add_option("-p", "--port", dest="port", help="Port number to query (for 24 hour summary).")
    parser.add_option("-s", "--show-queries", dest="show", action="store_true", help="Show query options.")
    (options, args) = parser.parse_args()

    if options.show:
        show_options()
    elif options.query != '6' and options.query != None:
        run_query(options.query)
    elif options.query == '6' and options.port != None:
        run_query(options.query, options.port)
    else:
        parser.print_help()
    sys.exit()

if __name__ == "__main__":
    main()
