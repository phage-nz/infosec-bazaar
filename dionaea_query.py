#!/usr/bin/python
import sqlite3
import sys
from optparse import OptionParser

# Dionaea Query Script v0.2
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


def run_query(query_num, query_port=None, query_ip=None, query_string=None, cut_after=None):
    if query_num == '1':
        queryDesc = "List of attacked ports."
        querySQL = 'SELECT local_port AS port, COUNT(local_port) AS hitcount FROM connections WHERE connection_type = "accept" GROUP BY local_port HAVING COUNT(local_port) > 10'
        queryColumns = ("Local Port", "Hits")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    elif query_num == '2':
        queryDesc = "Attacks over a day."
        querySQL = 'SELECT ROUND((connection_timestamp%(3600*24))/3600) AS hour, COUNT(*) FROM connections WHERE connection_parent IS NULL GROUP BY ROUND((connection_timestamp%(3600*24))/3600)'
        queryColumns = ("Hour", "Hits")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    elif query_num == '3':
        queryDesc = "Popular malware downloads."
        querySQL = 'SELECT download_md5_hash, COUNT(download_md5_hash) FROM downloads GROUP BY download_md5_hash ORDER BY COUNT(download_md5_hash) DESC LIMIT 10'
        queryColumns = ("MD5 Hash", "Submission Count")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    elif query_num == '4':
        queryDesc = "Busy attackers."
        querySQL = 'SELECT remote_host, COUNT(remote_host) FROM connections WHERE connection_type = "accept" GROUP BY remote_host ORDER BY COUNT(remote_host) DESC LIMIT 10'
        queryColumns = ("Remote Host", "Hits")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    elif query_num == '5':
        queryDesc = "Popular download locations."
        querySQL = 'SELECT COUNT(*),download_url FROM downloads GROUP BY download_url ORDER BY COUNT(*) DESC LIMIT 20'
        queryColumns = ("Hits", "Download URL")
        print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
        execute_query(querySQL)

    elif query_num == '6':
        isValidQuery = False
        if query_ip != None and query_port != None:
            querySQL = 'SELECT datetime(connection_timestamp, "unixepoch", "localtime"), remote_host, local_port, connection_transport, connection_protocol FROM connections WHERE connection_timestamp > strftime("%s", "now", "-1 day") AND remote_host = "{0}" AND local_port = "{1}"'.format(query_ip, query_port)
            isValidQuery = True
        elif query_ip != None:
            querySQL = 'SELECT datetime(connection_timestamp, "unixepoch", "localtime"), remote_host, local_port, connection_transport, connection_protocol FROM connections WHERE connection_timestamp > strftime("%s", "now", "-1 day") AND remote_host = "{0}"'.format(query_ip)
            isValidQuery = True
        elif query_port != None:
            querySQL = 'SELECT datetime(connection_timestamp, "unixepoch", "localtime"), remote_host, local_port, connection_transport, connection_protocol FROM connections WHERE connection_timestamp > strftime("%s", "now", "-1 day") AND local_port = "{0}"'.format(query_port)
            isValidQuery = True
        if isValidQuery:
            queryColumns = ("Time", "Remote IP", "Local Port", "Transport", "Protocol")
            queryDesc = "Connections in last 24hrs."
            print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
            execute_query(querySQL)
        else:
            print 'Invalid option(s). Valid options are:'
            list_options()

    elif query_num == '7':
        isValidQuery = False
        if query_string != None and cut_after != None:
            querySQL = 'SELECT substr(mysql_command_arg_data,0,{0}) from mysql_command_args where mysql_command_arg_data LIKE "%{1}%"'.format(cut_after, query_string)
            isValidQuery = True
        elif query_string != None:
            querySQL = 'SELECT mysql_command_arg_data from mysql_command_args where mysql_command_arg_data LIKE "%{0}%"'.format(query_string)
            isValidQuery = True
        if isValidQuery:
            queryDesc = "MySQL queries."
            queryColumns = ("Command")
            print "Description:\n\t{0}\nExecuted Query:\n\t{1}\n\n{2}".format(queryDesc, querySQL, queryColumns)
            execute_query(querySQL)
        else:
            print 'Invalid option(s). Valid options are:'
            list_options()
		
    else:
        print 'Invalid option(s). Valid options are:'
        list_options()


def list_options():
    print "\t1:\tPort attack frequency."
    print "\t2:\tAttacks over a day."
    print "\t3:\tPopular malware downloads."
    print "\t4:\tBusy attackers."
    print "\t5:\tPopular download locations."
    print "\t6:\tConnections in last 24hrs (requires explicit port and/or remote IP address definition)."
    print "\t7:\tMySQL queries (requires explicit search string definition)."


def main():
    parser = OptionParser(usage="%prog [-q] [-p] [-i] [-s]", version="%prog v0.2")
    parser.add_option("-q", "--query", dest="query", help="Number of the query to run.")
    parser.add_option("-p", "--port", dest="port", help="Port number to query (for 24 hour summary).")
    parser.add_option("-i", "--ip", dest="ip", help="IP address to query (for 24 hour summary).")
    parser.add_option("-s", "--string", dest="string", help="Search string (for string based queries).")
    parser.add_option("-c", "--cut-after", dest="cut", help="Number of characters to cut result down to (for string based queries).")	
    parser.add_option("-l", "--list-queries", dest="list", action="store_true", help="Show query options.")
    (options, args) = parser.parse_args()

    if options.list:
        show_options()
    elif options.query == '6' and options.port != None and options.ip != None:
        run_query(options.query, query_port=options.port, query_ip=options.ip)
    elif options.query == '6' and options.port != None:
        run_query(options.query, query_port=options.port)
    elif options.query == '6' and options.ip != None:
        run_query(options.query, query_ip=options.ip)
    elif options.query == '7' and options.string != None and options.cut != None:
        run_query(options.query, query_string=options.string, cut_after=options.cut)
    elif options.query == '7' and options.string != None:
        run_query(options.query, query_string=options.string)
    elif options.query != None:
        run_query(options.query)
    else:
        parser.print_help()
    sys.exit()

if __name__ == "__main__":
    main()
