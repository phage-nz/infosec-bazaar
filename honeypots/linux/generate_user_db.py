#!/usr/bin/python
import copy
import random
import string
import sqlite3

# Dionaea "Fake User" Database Creation Script v0.2
# By Chris Campbell
#
# https://www.twitter.com/phage_nz
# https://github.com/phage-nz
# https://bytefog.blogspot.com

# First run:
# sudo -u dionaea touch /opt/dionaea/var/dionaea/target_db.sqlite
# (where the path is the path to your user database).
#
# Requires a wordlist to be placed in the same directory as 'wordlist.txt'.

# Location of files.
db_file = "/opt/dionaea/var/dionaea/target_db.sqlite"
wordlist = "/opt/dionaea/var/dionaea/scripts/wordlist.txt"
# Email domains.
domains = [ "live.com", "gmail.com", "aol.com", "mail.com", "yahoo.com", "xtra.co.nz"]
# CC expiry years.
years = [ "2017", "2017", "2018", "2019" ]

visaPrefixList = [
        ['4', '5', '3', '9'],
        ['4', '5', '5', '6'],
        ['4', '9', '1', '6'],
        ['4', '5', '3', '2'],
        ['4', '9', '2', '9'],
        ['4', '0', '2', '4', '0', '0', '7', '1'],
        ['4', '4', '8', '6'],
        ['4', '7', '1', '6'],
        ['4']]

class fake_user:
    def __init__(self, username, password, email, cc, ccexpiry):
        self.username = username
        self.password = password
        self.email = email
        self.cc = cc
        self.ccexpiry = ccexpiry

def completed_number(prefix, length):
    ccnumber = prefix

    while len(ccnumber) < (length - 1):
        digit = str(random.choice(range(0, 10)))
        ccnumber.append(digit)

    sum = 0
    pos = 0

    reversedCCnumber = []
    reversedCCnumber.extend(ccnumber)
    reversedCCnumber.reverse()

    while pos < length - 1:
        odd = int(reversedCCnumber[pos]) * 2
        if odd > 9:
            odd -= 9
        sum += odd
        if pos != (length - 2):
            sum += int(reversedCCnumber[pos + 1])
        pos += 2

    checkdigit = ((sum / 10 + 1) * 10 - sum) % 10
    ccnumber.append(str(checkdigit))
    return ''.join(ccnumber)

def get_random_name():
    with open(wordlist, 'r') as f:
        words = f.readlines()
        randA = random.choice(words).rstrip('\r\n')
        randB = random.choice(words).rstrip('\r\n')
        return "{0}{1}".format(randA, randB)

def get_random_cc():
    prefix = random.choice(visaPrefixList)
    return completed_number(prefix, 16)
	
def get_random_expiry():
    return "{0:02d}/{1}".format(random.randint(1,12), random.choice(years))

def generate_random_user():
    username = get_random_name()
    email = "{0}@{1}".format(get_random_name(), random.choice(domains))
    password = ''.join(random.choice(string.ascii_letters) for x in range(random.randint(6,12)))
    cc = get_random_cc()
    ccexpiry = get_random_expiry()
    return fake_user(username, password, email, cc, ccexpiry)
    
def make_tables():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (username STRING, password STRING, email STRING, cc STRING, ccexpiry STRING)")
    conn.close()

def insert_users():
    number = random.randint(50,100)
    for x in range(0, number):
        user = generate_random_user()
        query = "INSERT INTO users (username, password, email, cc, ccexpiry) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}')".format(user.username, user.password, user.email, user.cc, user.ccexpiry)
        print "Creating user: {0}".format(user.username)
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        conn.close()


def main():
    make_tables()
    insert_users()

if __name__ == "__main__":
    main()