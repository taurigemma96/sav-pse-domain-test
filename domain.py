#importing basic libraries
import socket
import sys
from re import search
import datetime
from urllib.parse import urlparse

#the function responsible for returning the datetime object of a given url
def getDomainNameExpirationDate(url, time):
    #establishing a connection to the who-is databases via a socket opened on port 43
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = 'whois.internic.net'
    port = 43
    server_socket.connect((host,port))

    #sending a query to the who-is server
    server_socket.send(str.encode(url + "\r\n"))

    MAXLEN = 20000
    bytes_rcvd = 0
    expiration_date = time
    #parsing the response from the who-is server
    while bytes_rcvd < MAXLEN:
        raw_chunk  = server_socket.recv(2048)
        #if there is no response for the query, this error is thrown
        if raw_chunk == str.encode(''):
            raise RuntimeError("Invalid URL. The URL may be mistyped or may not exist.")
        bytes_rcvd = bytes_rcvd + len(raw_chunk)
        chunk = raw_chunk.decode()
        #determining whether or not the expiration date is in the current chunk of data being read
        if(search("Registry Expiry Date:", chunk)):
            for line in chunk.splitlines():
                #once the expiration date is found the data is parsed and converted from string and returned as a datetime object
                if(search("Registry Expiry Date:", line)):
                    data = line.strip().replace("Registry Expiry Date: ","").replace("Z","").split("T")
                    date = [int(i) for i in data[0].split('-')]
                    time = [int(j) for j in data[1].split(':')]
                    expiration_date = datetime.datetime(date[0], date[1], date[2], time[0], time[1], time[2])
                    return expiration_date
            break
    return expiration_date


#the function responsible for running an instance of the getDomainNameExpirationDate() function
def main():
    #retrieving the URL from the terminal and cleaning it to be sent to the who-is database
    url = ""
    while url == "":
        url = input("Please enter a valid URL for a .com domain:\n")
        o = urlparse(url)
        domain = o.netloc.split('.')
        if o.scheme == '':
            print("URL not valid. Please try again with a URL that starts with http://, or https://.")
            url = ""
        elif domain[len(domain)-1].strip() != 'com' and domain[len(domain)-1].strip() != '':
            print("URL not valid. Please try again with a URL that belongs to the .com domain.")
            url = ""
        elif len(domain) > 1 and domain[len(domain)-1].strip() == 'com':
            url = domain[len(domain)-2].strip() + '.' + domain[len(domain)-1].strip()
        else:
            print("URL not valid, please try again.")
            url = ""

    #getting the expiration date of the domain name url and determining whether or not the response from the function makes sense
    current_time = datetime.datetime.now()
    expiration_date = getDomainNameExpirationDate(url, current_time)
    #if everything is in order, output the expiration_date to the terminal
    if(current_time != expiration_date):
        print("Registry Expiry Date for " + url + ":", expiration_date)
    #if expiration_date and current_time are the same, then something went wrong with the response from the who-is server such as the expiration date not being present in the data data received
    else:
        print("Something went wrong, please try again.")
        main()
    

if __name__ == '__main__':
    main()