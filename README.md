docker build --force-rm --squash -t mini-sslscan .
docker image prune

in order to take che grade A ciphers
curl -s https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html | grep -A2 "<td>Advanced<br>(A)" | tail -n2 | sed -e 's/<[^>]*>//g'

