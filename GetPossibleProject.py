import requests
import json
from collections import Counter

def query_sourcegraph(function_name):
    url = "https://sourcegraph.com/.api/search/stream"
    params = {"q": f"context:global {function_name} count:1"}
    headers = {
        "Accept": "text/event-stream",
        "Authorization": "token sgp_a0d7ccb4f752ea73_a1fa205a23c8e6aa09b106e7c2fe8ae7f24154af"
    }
    response = requests.get(url, headers=headers, params=params, stream=True)

    repositories = []
    for line in response.iter_lines():
        if line.startswith(b"data:"):
            data = json.loads(line[5:])
            if isinstance(data, list) and data and "repository" in data[0]:
                repositories.append(data[0]["repository"])

    return repositories

def main():
    with open("unmatched_functions.txt", "r") as f:
        function_names = [line.strip() for line in f]

    project_counter = Counter()

    for function_name in function_names:
        print(f"Querying function: {function_name}")
        repositories = query_sourcegraph(function_name)
        print(f"Found {len(repositories)} occurrences")
        project_counter.update(repositories)
    print("\nProjects sorted by occurrence:")
    with open("projects.txt", "w") as f:
        for project, count in project_counter.most_common():
            print(f"{project}: {count}")
            f.write(f"{project}: {count}\n")


if __name__ == "__main__":
    main()
