*Admin Finder is a search tool that uses a basic code
python and pip as resource packages, this tool runs on a bruteforce system that uses a list of admin pages provided.*

Requirement :
- `Python 3.9.2`
- `pip 20.3.4`

Installing :
```
git clone --depth=1 https://github.com/sxlmnwb/sxlzptprjkt-admin-finder finder
cd finder
pip install -r requirements.txt
```
How To Usage :
```
usage: finder.py [-h] [-u URL] [-t] [-p PROXY] [-rp] [-r] [-v] [-U] [-i]

optional arguments:
    -h, --help               show this help message and exit
    -u URL, --url URL        Target URL (e.g. 'www.example.com' or 'example.com')
    -t, --tor                Use Tor anonymity network
    -p PROXY, --proxy PROXY  Use an HTTP proxy (e.g '127.0.0.1:8080')
    -rp, --random-proxy      Use randomly selected proxy server
    -r, --random-agent       Use randomly selected User-Agent
    -v, --verbose            Display more informations
    -U, --update             Update finder
    -i, --interactive        Interactive interface [other arguments not required]
```
Simple Usage :
```
./finder.py -u www.target.com -r
```
don't add `http://` or `https://` this finder works to detect whether the target is difficult to include SSL or not

**Disclaimer: For educational purpose only. Use at your own risk, it is very easy to detect such attempts**

*Credits : O.Koleda [Author], mIcHyAmRaNe [Base Build], sxlmnwb [Rebuild]*