import whois
import sys
if len(sys.argv) > 1:
  w = whois.whois(sys.argv[1])
  print w
