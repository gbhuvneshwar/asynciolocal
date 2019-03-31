# Example 1: synchronous requests
import requests

num_requests = 20

responses = [
    requests.get('http://example.org/')
    for i in range(num_requests)
]