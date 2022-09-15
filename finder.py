#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# // Copyright (C) 2022 Salman Wahib (sxlmnwb)
#

try:
    # Change main dir to this (need for Pentest Box)
    import os
    os.path.abspath(__file__)
    from Classes import (Credits,
                         FinderClass,
                         MessengeClass)
    import argparse
    from colorama import Fore, Back, Style
    import random
    import requests
    import socket
    import socks
    import subprocess
    import sys
    import time
    import threading
    from tqdm import tqdm
    import urllib.request, urllib.error, urllib.parse
    from urllib.request import urlopen

    # Get Messenge class to print information
    messenge = MessengeClass.Messenge()

except():
    exit('\n' + Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Session Cancelled Unknown Error'), 'bright')

# Get credits and print it
messenge.writeMessage(Credits.getCredits()[0], 'red')

# Get main class object
finder = FinderClass.Finder()

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30, width=90))
parser.add_argument("-u", "--url", default=False,
                    help="Target URL (e.g. 'www.example.com' or 'example.com')")
parser.add_argument("-t", "--tor", action='store_true', default=False,
                    help="Use Tor anonymity network")
parser.add_argument("-p", "--proxy", default=False,
                    help="Use an HTTP proxy (e.g '127.0.0.1:8080')")
parser.add_argument("-rp", "--random-proxy", action="store_true", default=False,
                    dest="random_proxy", help="Use randomly selected proxy server")
parser.add_argument("-r", "--random-agent", action='store_true', default=False,
                    dest='rand', help="Use randomly selected User-Agent")
parser.add_argument("-v", "--verbose", action='store_true', default=False,
                    help="Display more informations")
parser.add_argument("-U", "--update", action='store_true', default=False,
                    help="Update finder")
parser.add_argument("-i", "--interactive", action='store_true', default=False,
                    help="Interactive interface" + Fore.RED+Style.BRIGHT + " [other arguments not required]")
if len(sys.argv) <= 1:
    parser.print_usage()
    sys.exit(1)
else:
    args = parser.parse_args()

# site = 'testphp.vulnweb.com'
proxies = ""
headers = {'user-agent': 'finder/%s' % Credits.getCredits()[1]}
finder.header = headers

def url(site):
    try:
        if finder.checkUrl(site, proxies):
            messenge.writeMessage(Fore.GREEN + Style.BRIGHT + ('  [VULN]') + Fore.WHITE + Style.BRIGHT + '{:>}'.format(' http://' + site,), 'bright')
            messenge.writeMessage('')
            urls = tqdm(finder.getUrls('LinkFile/adminpanellinks.txt'), bar_format="{l_bar}{bar}|{n_fmt}/{total_fmt}{postfix}")
        else:
            messenge.writeMessage(Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Something Wrong With URL'), 'bright')
            urls = tqdm(finder.getUrls('LinkFile/adminpanellinks.txt'), bar_format="{bar}")
            exit(SystemExit)
        # Get links for checking

        # Counters for total links, and admin panel find
        totalCount = len(urls)
        adminCount = 0

        # Checking all links
        for url in urls:

            # Create test link with getting params from site and links.txt file
            reqLink = finder.createReqLink(site, url, proxies)
            # messenge.writeMessage('\t[#] Checking http://' + reqLink, 'yellow')
            urls.set_description(Fore.WHITE + Style.NORMAL + "  PROCESSING ")
            # Test created link for HTTPerrors. If not error - potential admin panel
            if finder.checkUrl(reqLink, proxies):
                adminCount += 1

                print()
                messenge.writeMessage('\n' + Fore.GREEN + Style.BRIGHT + ('  [RESULT]') + Fore.WHITE + Style.BRIGHT + '{:>}'.format(' http://' + reqLink,), 'bright')
                print()
                # Stopped process? and waiting for input for continue
                n = 10
                for x in range(totalCount):
                    #what to do every time.
                    if adminCount % n == 0:
                        #what to do every nth time.
                        messenge.writeInput('  Press' +Fore.BLUE+Style.BRIGHT+ ' ENTER ' +Fore.WHITE + Style.NORMAL + 'to continue scanning OR' +Fore.RED + Style.BRIGHT + ' CTRL+C ' + Fore.WHITE + Style.NORMAL + 'to cancel \n')
                        break
                    else:
                        continue

            # If HTTPerrors continue testing other links
            else:
                continue

        # Write last information about scanning with counters
        print()
        messenge.writeMessage(Fore.GREEN + Style.BRIGHT + ('  [COMPLETED]'), 'bright')
        print()
#       messenge.writeMessage(str(adminCount) + ' Admin Pages Found', 'white')
#       messenge.writeMessage(str(totalCount) + ' Total Pages Scanned', 'white')
        messenge.writeInput(Fore.YELLOW + Style.BRIGHT + ('  [/] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Scanning Over Press Enter To Exit...'), 'bright')
        messenge.writeMessage('', 'white')

    except (KeyboardInterrupt, SystemExit):
        messenge.writeMessage('\n' + Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Session Cancelled'), 'bright')
        urls.close()
        messenge.writeMessage('', 'white')

    except():
        messenge.writeMessage('\n' + Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Session Cancelled Unknown Error'), 'bright')
        messenge.writeMessage('', 'white')

def random_agent():
    useragent = "LinkFile/user-agent.txt"
    ua = open(useragent, 'r').read().splitlines()
    rua = random.choice(ua)
    headers = {'user-agent': rua}
    finder.header = headers
    return finder.header

def random_proxy():
    proxy_list = requests.get('https://raw.githubusercontent.com/a2u/free-proxy-list/master/free-proxy-list.txt').text.splitlines()
    random_proxy = random.choice(proxy_list)
    rip = random_proxy.rsplit(':', 1)[0] #random proxy ip
    rpp = random_proxy.rsplit(':', 1)[1] #random proxy port
    proxies = {
        'http': random_proxy,
        'https': random_proxy,
    }
    try:
        s = socks.socksocket()
        s.set_proxy(socks.HTTP, rip, rpp)
        socket.socket = socks.socksocket
        urllib.request.urlopen
    except (IndexError, IndentationError):
        messenge.writeMessage('\n\tSorry This [ERROR] ', 'red')
        quit(0)
    return proxies

def tor():
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, 'localhost', 9050)
    socket.socket = socks.socksocket
    urllib.request.urlopen

def proxy():
    args.proxy=str(args.proxy)
    proxies ={
    'http': args.proxy,
    'https': args.proxy,
    }
    try:
        ht = args.proxy.split(':')
        pr = int(ht[1])
        s = socks.socksocket()
        s.set_proxy(socks.HTTP, ht[0], pr)
        socket.socket = socks.socksocket
        urllib.request.urlopen
    except (IndexError, IndentationError):
        messenge.writeMessage('\n\tPlease check the format of your proxy | reminder: 127.0.0.1:8080 ', 'red')
        quit(0)
    try:
        print(Fore.BLUE + '\tChecking Http proxy...', end="\r")
        time.sleep(1)
        rp = requests.get('http://testphp.vulnweb.com', proxies=proxies, timeout=10)
        print(Fore.BLUE + '\tChecking Http proxy...', Fore.GREEN+Style.BRIGHT + 'OK\n' + Fore.WHITE + Style.NORMAL)
    except requests.RequestException:
        print(Fore.BLUE + '\tChecking Http proxy...', Fore.RED + Style.BRIGHT + 'BAD\n' + Fore.WHITE + Style.NORMAL)
        messenge.writeMessage('\n ╔═══[!] Connection Troubles [ERROR]', 'red')
        print(' ║')
        print(' ╚══►' + Fore.BLUE + '[Note]' + Fore.YELLOW + '╾╥──╸ Please check your connection, proxy or tor')
        print('            ╟──╸ ' + Fore.YELLOW+Style.BRIGHT + 'don\'t add' + Fore.YELLOW + Style.NORMAL + ' \'http://\' or \'https://\'')
        print('            ╙──╸ ' + Fore.YELLOW + Style.NORMAL + 'check that you have written the url correctly\n')
        quit(0)
    return proxies

def ipinf():
    ip = requests.get('http://ifconfig.co/ip', proxies=proxies, headers=finder.header).text
    cc = requests.get('http://ifconfig.co/country', proxies=proxies, headers=finder.header).text
    iso = requests.get('http://ifconfig.co/country-iso', proxies=proxies,  headers=finder.header).text
    city = requests.get('http://ifconfig.co/city', proxies=proxies,  headers=finder.header).text
    print('''    ┆
    ├───[''' + Fore.CYAN + '''IP address Infos:''' + Fore.YELLOW + ''']
    ┆''');
    print('    ├──► '+ Fore.BLUE +'Country: '+ cc + Fore.YELLOW +'    ├───► '+ Fore.BLUE +'IP: ' + ip + Fore.YELLOW + '    ├────► '+ Fore.BLUE +'Country ISO: ' + iso + Fore.YELLOW + '    └────► '+ Fore.BLUE +'City: ' + city)
    print('')

def vipinf():
    ip = requests.get('http://ifconfig.co/ip', proxies=proxies, headers=finder.header).text
    cc = requests.get('http://ifconfig.co/country', proxies=proxies, headers=finder.header).text
    iso = requests.get('http://ifconfig.co/country-iso', proxies=proxies, headers=finder.header).text
    city = requests.get('http://ifconfig.co/city', proxies=proxies,  headers=finder.header).text
    print('''
        ┌───[''' + Fore.CYAN + '''IP address Infos:''' + Fore.YELLOW + ''']
        ┆''');
    print('        ├──► ' + Fore.BLUE + 'Country: ' + cc + Fore.YELLOW + '        ├───► ' + Fore.BLUE + 'IP: ' + ip + Fore.YELLOW + '        ├────► ' + Fore.BLUE + 'Country ISO: ' + iso + Fore.YELLOW + '        └─────► '+ Fore.BLUE +'City: ' + city)
    print('')

def hos():
    site = args.url
    rh = requests.get('http://'+site,proxies=proxies, headers=finder.header)

    di = socket.gethostbyname(site)
    print(Fore.CYAN + Style.BRIGHT + '\tServer: ' + Fore.YELLOW + rh.headers['Server'] + '\t\t' + Fore.CYAN + Style.BRIGHT +'Hostname: ' + Fore.YELLOW + di + '\n')
    try:
        xf = dict(rh.headers).get("x-frame-options")
        xf = str(xf)
        print(Fore.CYAN + Style.BRIGHT +'\tX-Powered-By: ' + Fore.YELLOW + rh.headers['X-Powered-By'] + '\t\t' + Fore.CYAN + Style.BRIGHT + 'X-Frame-Options: ' + Fore.YELLOW + xf + '\n\n')
    except KeyError:
        pass

def update():
    process = subprocess.Popen(["git", "pull"], stdout=subprocess.PIPE)
    output = process.communicate()[0].decode("utf-8")
    print(output)

def interactive():
    try:
        # Random UserAgent
        #Useragents are from: https://techblog.willshouse.com/2012/01/03/most-common-user-agents/
        try:
            print(Fore.BLUE + '\tGetting random user-agent...', end="\r")
            time.sleep(1)
            useragent = "LinkFile/user-agent.txt"
            ua = open(useragent, 'r').read().splitlines()
            rua = random.choice(ua)
            headers = {'user-agent': rua}
            print(Fore.BLUE + '\tGetting random user-agent...', Fore.GREEN+Style.BRIGHT + 'DONE\n' + Fore.WHITE + Style.NORMAL)
        except:
            headers = {'user-agent': 'finder/%s' % Credits.getCredits()[1]}
            pass
        finder.header = headers

        # Additional params
        # if not messenge.writeInputWithYesNo(Fore.YELLOW + '  Do you want use default params?'):
        #     timeout = messenge.writeInput(Fore.YELLOW + '  Change timeout. Please write value in seconds: ' + Fore.GREEN)
        #     finder.timeout = timeout

        #Updater

        #network params
        choice=''
        print(Fore.YELLOW + '    ┌───[' + Fore.CYAN + 'Network settings:' + Fore.YELLOW + ']');
        while (choice not in ['1','2','3','tor','proxy']):
            choice=input(Fore.YELLOW + '''    ┊
    ├╼[1] tor
    ├╼[2] proxy
    ├╼[3] nothing
    ┊
    └───╼''' + Fore.RED + ''' Please choose one option''' + Fore.YELLOW + ''' ~$ ''')
            if choice == '1' or choice == 'tor':
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, 'localhost', 9050)
                socket.socket = socks.socksocket
                urllib.request.urlopen
                proxies=""

            elif choice == '2' or choice == 'proxy':
                prox = input('''    ┊
    └────► set your HTTP proxy {example:127.0.0.1:80} : ~$ ''')
                proxies = {
                  'http': 'http://'+prox,
                  'https': 'http://'+prox,
                }
                try:
                    ht = prox.split(':')
                    pr = int(ht[1])
                    s = socks.socksocket()
                    s.set_proxy(socks.HTTP, ht[0], pr)
                    socket.socket = socks.socksocket
                    urllib.request.urlopen
                except IndexError:
                    messenge.writeMessage('\n\tPlease check the format of your proxy | reminder: 127.0.0.1:8080 ', 'red')
                    quit(0)

            else:
                proxies = ""
                continue

        ip = requests.get('http://ifconfig.co/ip', proxies=proxies, headers=finder.header).text
        cc = requests.get('http://ifconfig.co/country', proxies=proxies, headers=finder.header).text
        iso = requests.get('http://ifconfig.co/country-iso', proxies=proxies, headers=finder.header).text
        city = requests.get('http://ifconfig.co/city', proxies=proxies,  headers=finder.header).text

        print('''    ┆
    ├───[''' + Fore.CYAN + '''IP address Infos:''' + Fore.YELLOW + ''']
    ┆''');
        print('    ├──► ' + Fore.BLUE +'Country: ' + cc + Fore.YELLOW + '    ├───► ' + Fore.BLUE +'IP: ' + ip + Fore.YELLOW + '    ├────► '+ Fore.BLUE + 'Country ISO: ' + iso + Fore.YELLOW + '    └─────► '+ Fore.BLUE +'City: ' + city)
        print('')
        # Get site
        site = messenge.writeInput('  Enter Site Name  { example : example.com or www.example.com } \n' + Fore.BLUE + ' ~$ ', 'white');
        print ('')
        # Checking if the website is online and stable
        if finder.checkUrl(site,proxies):
            messenge.writeMessage(Fore.GREEN + Style.BRIGHT + ('  [VULN]') + Fore.WHITE + Style.BRIGHT + '{:>}'.format(' http://' + site,), 'bright')
            messenge.writeMessage('')
        else:
            messenge.writeMessage(Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Something Wrong With URL'), 'bright')
            exit(SystemExit)

        #Some additional info about the website
        rh = requests.get('http://'+site, proxies=proxies, headers=finder.header)

        di = socket.gethostbyname(site)
        print(Fore.CYAN + Style.BRIGHT + '\tServer: ' + Fore.YELLOW + rh.headers['Server'] + '\t\t' + Fore.CYAN + Style.BRIGHT +'Hostname: ' + Fore.YELLOW + di + '\n')
        try:
            xf = dict(rh.headers).get("x-frame-options")
            xf = str(xf)
            print(Fore.CYAN + Style.BRIGHT + '\tX-Powered-By: ' + Fore.YELLOW + rh.headers['X-Powered-By'] + '\t\t' + Fore.CYAN+Style.BRIGHT + 'X-Frame-Options: ' + Fore.YELLOW + xf + '\n\n')
        except KeyError:
            pass

        # Get links for checking
        urls = finder.getUrls('LinkFile/adminpanellinks.txt')

        # Counters for total links, and admin panel find
        totalCount = len(urls)
        adminCount = 0

        # Checking all links
        for url in urls:

            # Create test link with getting params from input and links.txt file
            reqLink = finder.createReqLink(site, url, proxies)
            messenge.writeMessage('\t[#] Checking http://' + reqLink, 'yellow')

            # Test created link for HTTPerrors. If not error - potential admin panel
            if finder.checkUrl(reqLink,proxies):
                adminCount += 1
                messenge.writeMessage('  %s %s' % ('\n  [✔] http://' + reqLink, 'Admin page found!'), 'bright')

                # Stopped process? and waiting for input for continue
                messenge.writeInput('  Press enter to continue scanning.\n')

            # If HTTPerrors continue testing other links
            else:
                continue

        # Write last information about scanning with counters
        print()
        messenge.writeMessage(Fore.GREEN + Style.BRIGHT + ('  [COMPLETED]'), 'bright')
        print()
#       messenge.writeMessage(str(adminCount) + ' Admin Pages Found', 'white')
#       messenge.writeMessage(str(totalCount) + ' Total Pages Scanned', 'white')
        messenge.writeInput(Fore.YELLOW + Style.BRIGHT + ('  [/] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Scanning Over Press Enter To Exit...'), 'bright')
        messenge.writeMessage('', 'white')

    except (KeyboardInterrupt, SystemExit):
        messenge.writeMessage('\n' + Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Session Cancelled'), 'bright')
        messenge.writeMessage('', 'white')

    except():
        messenge.writeMessage('\n' + Fore.RED + Style.BRIGHT + ('  [ERROR] ') + Fore.WHITE + Style.NORMAL + '{:>}'.format('Session Cancelled Unknown Error'), 'bright')
        messenge.writeMessage('', 'white')


if __name__ == '__main__':
    # Updater
    if args.update:
        args.url = False
        args.tor = False
        args.rand = False
        args.proxy = False
        args.verbose = False
        args.interactive = False
        update()

    # interactive
    if args.interactive:
        args.url = False
        args.tor = False
        args.rand = False
        args.proxy = False
        args.verbose = False
        interactive()

    # random user-agent
    if args.rand:
        if args.url is False:
            parser.print_usage()
            quit(0)
        else:
            random_agent()

    # random proxy
    if args.random_proxy:
        if args.url is False:
            parser.print_usage()
            quit(0)
        else:
            random_proxy()
            proxies = random_proxy()

    # tor
    if args.tor:
        if args.url is False:
            parser.print_usage()
            quit(0)
        else:
            tor()

    # proxy
    if args.proxy:
        if args.url is False:
            parser.print_usage()
            quit(0)
        else:
            proxy()
            proxies = proxy()

    # verbose
    if args.verbose:
        if args.url is False:
            parser.print_usage()
            quit(0)
        else:
            vipinf()
            hos()

    # url
    if args.url:
        site = args.url
        # proxies=""
        url(site)
