import requests
import json
import time

def obtener_issues(repo_owner, repo_name, headers=None, estado='all', max_paginas=100):

    all_issues = []
    page = 1
    max_results = 100

    while True:
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues?state={estado}&page={page}&per_page={max_results}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            issues = response.json()
            if not issues:
                break
            
            for issue in issues:
                issue_data = {
                    'number': issue['number'],
                    'title': issue['title'],
                    'state': issue['state'],
                    'url': issue['html_url'],
                    'description': issue['body'],
                    'labels': [label['name'] for label in issue['labels']],
                    'created_at': issue['created_at'],
                    'updated_at': issue['updated_at'],
                    'closed_at': issue['closed_at'],
                    'user': issue['user']['login']
                }
                all_issues.append(issue_data)

            # esta parte maneja el apartado para las
            if 'Link' in response.headers:
                links = response.headers['Link'].split(',')
                next_page = None
                for link in links:
                    if 'rel="next"' in link:
                        next_page = link[link.find("<")+1:link.find(">")]
                        break
                if next_page is None:
                    break
                else:
                    page += 1
                    time.sleep(1)  # Espera de 1 segundo para no exceder el límite de peticiones
            else:
                break
        
            if max_paginas is not None and page > max_paginas: #Verifica que no se ha excedido el numero de paginas
                break
        else:
            print(f"Error al obtener los issues: {response.status_code}")
            print(response.text)
            return None

    return all_issues
#Guarda los archivos en formato JSON
def guardar_issues_json(issues, nombre_archivo): 
    with open(nombre_archivo, 'w', encoding='utf-8') as f:
        json.dump(issues, f, indent=4, ensure_ascii=False) 

# --- Programa principal ---
if __name__ == "__main__":
    repo_owner = "cp2k"  # Reemplaza con el propietario del repositorio
    repo_name = "cp2k"   # Reemplaza con el nombre del repositorio
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': 'token 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'  # Reemplazar con el token
    }

    issues = obtener_issues(repo_owner, repo_name, headers, max_paginas=100) 

    if issues:
        print(f"Se obtuvieron {len(issues)} issues del repositorio {repo_owner}/{repo_name}")
        nombre_archivo = f"{repo_owner}_{repo_name}_issues.json"
        guardar_issues_json(issues, nombre_archivo)
        print(f"Los issues se han guardado en el archivo: {nombre_archivo}")
    else:
        print("No se pudieron obtener los issues.")