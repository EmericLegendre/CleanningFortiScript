import time
import requests
import json
import argparse
import os
import pandas as pd
from datetime import datetime, timedelta
import getpass
 
# Désactiver les warnings SSL
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
 
def fortimanager_login(fmg_ip, fmg_admin_user, fmg_admin_password):
    """Authentification à FortiManager et récupération de la session."""
    try:
        fmg_url = f"https://{fmg_ip}/jsonrpc"
        login_payload = {
            "id": 1,
            "method": "exec",
            "params": [{"url": "sys/login/user", "data": [{"user": fmg_admin_user, "passwd": fmg_admin_password}]}]
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=login_payload, verify=False)
        response.raise_for_status()
        result = response.json()
        if "session" in result:
            print("✅ Connexion à FortiManager réussie.")
            return result["session"]
        else:
            print("❌ Erreur de connexion:", result)
            exit(-1)
    except Exception as e:
        print(f"❌ Erreur lors de la connexion à FortiManager: {e}")
        exit(-1)
 
def fortimanager_logout(fmg_url, session):
    """Déconnexion de FortiManager."""
    try:
        logout_payload = {
            "id": 2,
            "method": "exec",
            "session": session,
            "params": [{"url": "sys/logout"}]
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=logout_payload, verify=False)
        response.raise_for_status()
        print("✅ Déconnexion réussie.")
    except Exception as e:
        print(f"❌ Erreur lors de la déconnexion: {e}")
 
def get_adoms(fmg_url, session):
    """Récupérer la liste des ADOMs."""
    try:
        payload = {"id": 3, "method": "get", "session": session, "params": [{"url": "/dvmdb/adom"}]}
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        adoms = [adom['name'] for adom in response.json().get("result", [{}])[0].get("data", [])]
        print(f"✅ Liste des ADOMs récupérée: {adoms}")
        return adoms
    except Exception as e:
        print(f"❌ Erreur lors de la récupération des ADOMs: {e}")
        return []
 
def get_packages_in_adom(fmg_url, session, adom):
    """Récupérer la liste des packages dans un ADOM."""
    try:
        payload = {"id": 4, "method": "get", "session": session, "params": [{"url": f"/pm/pkg/adom/{adom}"}]}
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        packages = [pkg['name'] for pkg in response.json().get("result", [{}])[0].get("data", [])]
        print(f"✅ Liste des packages récupérée pour l'ADOM {adom}: {packages}")
        return packages
    except Exception as e:
        print(f"❌ Erreur lors de la récupération des packages pour l'ADOM {adom}: {e}")
        return []
 
def get_policies_in_package(fmg_url, session, adom, package_name):
    """Récupérer la liste des politiques dans un package."""
    try:
        payload = {"id": 5, "method": "get", "session": session, "params": [{"url": f"/pm/config/adom/{adom}/pkg/{package_name}/firewall/policy", "fields": [
                "extra info"
            ]}]}
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        policies = response.json().get("result", [{}])[0].get("data", [])
        print(policies)
        print(f"✅ Liste des politiques récupérée pour le package {package_name} dans l'ADOM {adom}.")
        return policies
    except Exception as e:
        print(f"❌ Erreur lors de la récupération des politiques pour le package {package_name} dans l'ADOM {adom}: {e}")
        return []
 
def trigger_hit_count_task(fmg_url, session, adom, package_name):
    """Déclencher la tâche de comptage des hits et retourner l'ID de la tâche."""
    try:
        payload = {
            "id": 6,
            "method": "exec",
            "params": [
                {
                    "url": "/sys/hitcount",
                    "data": {
                        "adom": adom,
                        "pkg": package_name
                    }
                }
            ],
            "session": session
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        result = response.json()
        task_id = result.get("result", [{}])[0].get("data", {}).get("task")
        if not task_id:
            raise Exception("Failed to retrieve task ID from hit count response.")
        print(f"✅ Tâche de comptage des hits déclenchée avec succès. ID de la tâche: {task_id}")
        return task_id
    except Exception as e:
        print(f"❌ Erreur lors du déclenchement de la tâche de comptage des hits: {e}")
        return None
 
def monitor_task(fmg_url, session, task_id):
    """Surveiller l'état d'une tâche jusqu'à son achèvement."""
    try:
        while True:
            payload = {
                "id": 7,
                "method": "get",
                "params": [{"url": f"/task/task/{task_id}"}],
                "session": session,
                "verbose": 1
            }
            headers = {'Content-Type': 'application/json'}
            response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
            response.raise_for_status()
            task_data = response.json()
            task_status = task_data.get("result", [{}])[0].get("data", {}).get("state")
 
            if task_status == "done":
                print(f"✅ Tâche {task_id} terminée avec succès.")
                return "done"
            elif task_status == "error":
                raise Exception(f"❌ Tâche {task_id} a échoué.")
            else:
                print(f"⏳ Tâche {task_id} en cours...")
                time.sleep(5)
    except Exception as e:
        print(f"❌ Erreur lors de la surveillance de la tâche {task_id}: {e}")
        return "error"
 
def get_task_result(fmg_url, session, task_id):
    """Récupérer le résultat d'une tâche."""
    try:
        payload = {
            "id": 8,
            "method": "exec",
            "params": [{"data": {"taskid": task_id}, "url": "/sys/task/result"}],
            "session": session
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        result = response.json()
        print(f"✅ Résultat de la tâche {task_id} récupéré avec succès.")
        return result
    except Exception as e:
        print(f"❌ Erreur lors de la récupération du résultat de la tâche {task_id}: {e}")
        return None
 
def filter_unused_policies(policies, task_result, adom, package, days, logic=1):
    """Filtrer les politiques inutilisées."""
    try:
        unused_policies = []
        delta = int((datetime.now() - timedelta(days)).timestamp())
        hitcount_data = task_result.get("result", [{}])[0].get("data", {}).get("firewall policy", [])
 
        for policy in policies:
            policy_id = policy.get("policyid")
            matching_policy = next((p for p in hitcount_data if p["policyid"] == policy_id), None)
            
            if matching_policy:
                hitcount = matching_policy.get("hitcount", 0)
                last_hit = matching_policy.get("last_hit", 0)
                created_timestamp = policy.get("_created timestamp", 0)

                match logic:
                    case 1:
                        if ( (hitcount == 0 and created_timestamp <= delta) or (hitcount != 0 and last_hit <= delta) ):
                            policy["hitcount"] = hitcount
                            policy["last_hit"] = last_hit
                            policy["adom"] = adom
                            policy["package"] = package
                            unused_policies.append(policy)
                    case 2:
                        if hitcount == 0 or last_hit <= delta:
                            policy["hitcount"] = hitcount
                            policy["last_hit"] = last_hit
                            policy["adom"] = adom
                            policy["package"] = package
                            unused_policies.append(policy)
                    case 3:
                        if hitcount == 0:
                            policy["hitcount"] = hitcount
                            policy["last_hit"] = last_hit
                            policy["adom"] = adom
                            policy["package"] = package
                            unused_policies.append(policy)
                    case 4:
                        if hitcount != 0 and last_hit <= delta:
                            policy["hitcount"] = hitcount
                            policy["last_hit"] = last_hit
                            policy["adom"] = adom
                            policy["package"] = package
                            unused_policies.append(policy)
                    case 5:
                        if created_timestamp <= delta:
                            policy["hitcount"] = hitcount
                            policy["last_hit"] = last_hit
                            policy["adom"] = adom
                            policy["package"] = package
                            unused_policies.append(policy)
 
        print(f"✅ Politiques inutilisées filtrées pour l'ADOM {adom} et le package {package}.")
        return unused_policies
    except Exception as e:
        print(f"❌ Erreur lors du filtrage des politiques inutilisées: {e}")
        return []
 
def delete_policy(fmg_url, session, adom, package_name, policy_id):
    """Supprimer une politique."""
    try:
        payload = {
            "id": 9,
            "method": "delete",
            "session": session,
            "params": [{"url": f"/pm/config/adom/{adom}/pkg/{package_name}/firewall/policy/{policy_id}"}]
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        print(f"✅ Politique {policy_id} supprimée dans {package_name} ({adom}).")
    except Exception as e:
        print(f"❌ Erreur lors de la suppression de la politique {policy_id} dans {package_name} ({adom}): {e}")
 
def save_to_json(data, filename):
    """Sauvegarder les données en JSON."""
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
            existing_data.extend(data)
            data = existing_data
 
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"✅ Fichier JSON créé/mis à jour : {filename}")
    except Exception as e:
        print(f"❌ Erreur lors de la sauvegarde en JSON: {e}")
 
def save_to_excel(data, filename):
    """Sauvegarder les données en Excel."""
    try:
        if os.path.exists(filename):
            df_existing = pd.read_excel(filename)
            df_new = pd.DataFrame(data)
            df = pd.concat([df_existing, df_new], ignore_index=True)
        else:
            df = pd.DataFrame(data)
 
        df.to_excel(filename, index=False)
        print(f"✅ Fichier Excel créé/mis à jour : {filename}")
    except Exception as e:
        print(f"❌ Erreur lors de la sauvegarde en Excel: {e}")
 
def restore_policies(fmg_url, session, policies):
    """Restaurer les politiques depuis un fichier de backup."""
    try:
        for policy in policies:
            payload = {
                "id": 10,
                "method": "add",
                "session": session,
                "params": [{
                    "url": f"/pm/config/adom/{policy['adom']}/pkg/{policy['package']}/firewall/policy",
                    "data": {
                        "name": policy.get('name'),
                        "policyid": policy.get('policyid'),
                        "action": policy.get('action'),
                        "dstaddr": policy.get('dstaddr', []),
                        "dstintf": policy.get('dstintf', []),
                        "logtraffic": policy.get('logtraffic'),
                        "schedule": policy.get('schedule'),
                        "service": policy.get('service', []),
                        "srcaddr": policy.get('srcaddr', []),
                        "srcintf": policy.get('srcintf', []),
                        "status": policy.get('status'),
                        "vpn_dst_node": policy.get('vpn_dst_node'),
                        "vpn_src_node": policy.get('vpn_src_node'),
                        "srcaddr6": policy.get('srcaddr6', ''),
                        "dstaddr6": policy.get('dstaddr6', ''),
                        "tcp-mss-sender": policy.get('tcp-mss-sender'),
                        "tcp-mss-receiver": policy.get('tcp-mss-receiver'),
                        "groups": policy.get('groups'),
                        "custom-log-fields": policy.get('custom-log-fields'),
                        "uuid": policy.get('uuid'),
                        "wccp": policy.get('wccp'),
                        "session-ttl": policy.get('session-ttl'),
                        "match-vip": policy.get('match-vip'),
                        "rtp-nat": policy.get('rtp-nat'),
                        "webfilter-profile": policy.get('webfilter-profile'),
                        "schedule-timeout": policy.get('schedule-timeout'),
                        "fsso-agent-for-ntlm": policy.get('fsso-agent-for-ntlm'),
                        "logtraffic-start": policy.get('logtraffic-start'),
                        "block-notification": policy.get('block-notification'),
                        "srcaddr-negate": policy.get('srcaddr-negate'),
                        "dstaddr-negate": policy.get('dstaddr-negate'),
                        "service-negate": policy.get('service-negate'),
                        "permit-any-host": policy.get('permit-any-host'),
                        "send-deny-packet": policy.get('send-deny-packet'),
                        "_label-color": policy.get('_label-color'),
                        "policy-expiry": policy.get('policy-expiry'),
                        "policy-expiry-date": policy.get('policy-expiry-date'),
                        "internet-service": policy.get('internet-service'),
                        "reputation-minimum": policy.get('reputation-minimum'),
                        "geoip-anycast": policy.get('geoip-anycast'),
                        "anti-replay": policy.get('anti-replay'),
                        "inspection-mode": policy.get('inspection-mode'),
                        "email-collect": policy.get('email-collect'),
                        "match-vip-only": policy.get('match-vip-only'),
                        "fsso-groups": policy.get('fsso-groups'),
                        "geoip-match": policy.get('geoip-match'),
                        "internet-service-src-name": policy.get('internet-service-src-name'),
                        "src-vendor-mac": policy.get('src-vendor-mac'),
                        "file-filter-profile": policy.get('file-filter-profile'),
                        "policy-offload": policy.get('policy-offload'),
                        "cgn-session-quota": policy.get('cgn-session-quota'),
                        "cgn-resource-quota": policy.get('cgn-resource-quota'),
                        "ztna-status": policy.get('ztna-status'),
                        "ztna-ems-tag": policy.get('ztna-ems-tag'),
                        "videofilter-profile": policy.get('videofilter-profile'),
                        "dynamic-shaping": policy.get('dynamic-shaping'),
                        "nat64": policy.get('nat64'),
                        "nat46": policy.get('nat46'),
                        "sctp-filter-profile": policy.get('sctp-filter-profile'),
                        "sgt-check": policy.get('sgt-check'),
                        "sgt": policy.get('sgt'),
                        "fec": policy.get('fec'),
                        "ztna-tags-match-logic": policy.get('ztna-tags-match-logic'),
                        "tcp-timeout-pid": policy.get('tcp-timeout-pid'),
                        "udp-timeout-pid": policy.get('udp-timeout-pid'),
                        "internet-service6": policy.get('internet-service6'),
                        "internet-service6-src": policy.get('internet-service6-src'),
                        "reputation-minimum6": policy.get('reputation-minimum6'),
                        "reputation-direction6": policy.get('reputation-direction6'),
                        "network-service-dynamic": policy.get('network-service-dynamic'),
                        "network-service-src-dynamic": policy.get('network-service-src-dynamic'),
                        "srcaddr6-negate": policy.get('srcaddr6-negate'),
                        "dstaddr6-negate": policy.get('dstaddr6-negate'),
                        "ztna-device-ownership": policy.get('ztna-device-ownership'),
                        "ztna-policy-redirect": policy.get('ztna-policy-redirect'),
                        "policy-behaviour-type": policy.get('policy-behaviour-type'),
                        "ip-version-type": policy.get('ip-version-type'),
                        "ips-voip-filter": policy.get('ips-voip-filter'),
                    }
                }]
            }
            headers = {'Content-Type': 'application/json'}
            response = requests.post(fmg_url, headers=headers, json=payload, verify=False)
            print(response.json())
            response.raise_for_status()
            print(f"✅ Politique restaurée : {policy['name']} (ID: {policy['policyid']}) dans {policy['package']} ({policy['adom']}).")
    except Exception as e:
        print(f"❌ Erreur lors de la restauration des politiques: {e}")
 
def load_policies_from_backup(backup_file):
    """Charger les politiques depuis un fichier de backup."""
    try:
        if not os.path.exists(backup_file):
            print("❌ Fichier de sauvegarde introuvable.")
            return []
        with open(backup_file, 'r') as file:
            policies = json.load(file)
            print(f"✅ Politiques chargées depuis le fichier de backup: {backup_file}")
            return policies
    except Exception as e:
        print(f"❌ Erreur lors du chargement des politiques depuis le fichier de backup: {e}")
        return []

def lock_adom(fmg_url, session_id, adom_name):
    """Verrouille un ADOM dans FortiManager (workspace lock)."""
    try:
        lock_payload = {
            "id": 2,
            "method": "exec",
            "params": [
                {
                    "url": f"/dvmdb/adom/{adom_name}/workspace/lock"
                }
            ],
            "session": session_id
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=lock_payload, verify=False)
        response.raise_for_status()
        result = response.json()

        if result.get("result", [{}])[0].get("status", {}).get("code") == 0:
            print(f"🔒 ADOM '{adom_name}' verrouillé avec succès.")
        else:
            print(f"⚠️ Erreur lors du verrouillage de l'ADOM : {result}")
            exit(-1)
    except Exception as e:
        print(f"❌ Exception lors du verrouillage de l'ADOM : {e}")
        exit(-1)

def unlock_adom(fmg_url, session_id, adom_name):
    """Déverrouille un ADOM dans FortiManager (workspace unlock)."""
    try:
        unlock_payload = {
            "id": 3,
            "method": "exec",
            "params": [
                {
                    "url": f"/dvmdb/adom/{adom_name}/workspace/unlock"
                }
            ],
            "session": session_id
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=unlock_payload, verify=False)
        response.raise_for_status()
        result = response.json()

        if result.get("result", [{}])[0].get("status", {}).get("code") == 0:
            print(f"🔓 ADOM '{adom_name}' déverrouillé avec succès.")
        else:
            print(f"⚠️ Erreur lors du déverrouillage de l'ADOM : {result}")
            exit(-1)
    except Exception as e:
        print(f"❌ Exception lors du déverrouillage de l'ADOM : {e}")
        exit(-1)

def commit_adom(fmg_url, session_id, adom_name):
    """Commit les modifications faites dans l’ADOM (en mode workspace)."""
    try:
        commit_payload = {
            "id": 4,
            "method": "exec",
            "params": [
                {
                    "url": f"/dvmdb/adom/{adom_name}/workspace/commit"
                }
            ],
            "session": session_id
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(fmg_url, headers=headers, json=commit_payload, verify=False)
        response.raise_for_status()
        result = response.json()

        if result.get("result", [{}])[0].get("status", {}).get("code") == 0:
            print(f"✅ Modifications commit dans l’ADOM '{adom_name}'.")
        else:
            print(f"⚠️ Erreur lors du commit : {result}")
            fortimanager_logout(fmg_url, session)
            exit(-1)
    except Exception as e:
        print(f"❌ Exception lors du commit : {e}")
        exit(-1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", type=str, required=True, help="Adresse IP de FortiManager")
    parser.add_argument("--user", type=str, required=True, help="Nom d'utilisateur")
    parser.add_argument("--delete", action="store_true", help="Supprimer les politiques inutilisées")
    parser.add_argument("--restore", type=str, help="Restaurer les politiques depuis un fichier de backup (format: YYYYMMDD_HHMMSS)")
    parser.add_argument("--days", type=int, default=365, help="Nombre de jours pour considérer une politique comme inutilisée")
    args = parser.parse_args()

    fmg_password = getpass.getpass("Entrez le mot de passe: ")

    fmg_url = f"https://{args.url}/jsonrpc"
    session = fortimanager_login(args.url, args.user, fmg_password)

    if args.delete:
        days = args.days
        print("❓ Quel mode de suppression voulez-vous utiliser ?")
        print(f"1. Hit-count = 0 et date-de-creation > {days} jours ou hit-count = 0 et last-used > {days} jours")
        print(f"2. hit-count = 0 ou last-used > {days} jours")
        print(f"3. hit-count = 0")
        print(f"4. last-used > {days} jours")
        print(f"5. date-de-creation > {days} jours")
        logic_input = input("Entrez le numéro du mode de suppression (1/2/3/4/5): ")

        match logic_input:
            case "1":
                logic = 1
            case "2":
                logic = 2
            case "3":
                logic = 3
            case "4":
                logic = 4
            case "5":
                logic = 5
            case _:
                print("❌ Mode de suppression invalide. Utilisation du mode par défaut (1)")
                logic = 1
        print(f"✅ Mode de suppression sélectionné: {logic}")

        adoms = get_adoms(fmg_url, session)
        if adoms:
            print("📌 Liste des ADOMs disponibles:")
            for i, adom in enumerate(adoms, 1):
                print(f"{i}. {adom}")

            while True:
                try:
                    selected_indices = input("Sélectionnez un ou plusieurs ADOMs (numéros séparés par des virgules, ex: 1,3,5): ")
                    selected_indices = [int(idx.strip()) - 1 for idx in selected_indices.split(",")]
                    selected_adoms = [adoms[idx] for idx in selected_indices]
                    break
                except (ValueError, IndexError):
                    print("❌ Sélection invalide. Veuillez entrer des numéros valides séparés par des virgules.")

            print(f"✅ ADOMs sélectionnés: {', '.join(selected_adoms)}")

            for selected_adom in selected_adoms:
                lock_adom(fmg_url, session, selected_adom)
                print(f"🔒 ADOM '{selected_adom}' verrouillé.")

                packages = get_packages_in_adom(fmg_url, session, selected_adom)
                unused_policies_list = []

                for package in packages:
                    
                    policies = get_policies_in_package(fmg_url, session, selected_adom, package)
                    if policies:
                        print(selected_adom, package)
                        task_id = trigger_hit_count_task(fmg_url, session, selected_adom, package)
                        if task_id:
                            status = monitor_task(fmg_url, session, task_id)
                            if status == "done":
                                task_result = get_task_result(fmg_url, session, task_id)
                                print(task_result)
                                if task_result:
                                    unused = filter_unused_policies(policies, task_result, selected_adom, package, days, logic)
                                    unused_policies_list.extend(unused)

                if unused_policies_list:
                    timestamp = datetime.now().strftime("%Y-%m-%d_%Hh%M")
                    backup_filename_json = f"unused_policies_backup_{selected_adom}_{timestamp}.json"
                    backup_filename_excel = f"unused_policies_backup_{selected_adom}_{timestamp}.xlsx"

                    save_to_json(unused_policies_list, backup_filename_json)
                    save_to_excel(unused_policies_list, backup_filename_excel)

                    print(f"📌 {len(unused_policies_list)} politiques inutilisées trouvées dans l’ADOM '{selected_adom}'.")

                    confirmation = input(f"\nVoulez-vous supprimer ces politiques dans l’ADOM '{selected_adom}' ? (oui/non): ").strip().lower()
                    if confirmation == "oui":
                        for policy in unused_policies_list:
                            delete_policy(fmg_url, session, policy['adom'], policy['package'], policy['policyid'])

                        commit_adom(fmg_url, session, selected_adom)
                        unlock_adom(fmg_url, session, selected_adom)

                        print(f"✅ Suppression + commit + unlock terminés pour l’ADOM '{selected_adom}'.")
                    else:
                        unlock_adom(fmg_url, session, selected_adom)
                        print(f"🔓 ADOM '{selected_adom}' déverrouillé sans suppression.")
                else:
                    unlock_adom(fmg_url, session, selected_adom)
                    print(f"✅ Aucune politique inutilisée trouvée dans l’ADOM '{selected_adom}'.")
        else:
            print("❌ Aucun ADOM trouvé.")

    elif args.restore:
        backup_file = f"unused_policies_backup_{args.restore}.json"
        policies_to_restore = load_policies_from_backup(backup_file)

        if policies_to_restore:
            # Récupérer tous les ADOMs concernés dans le fichier de backup
            adoms_in_backup = list(set(policy['adom'] for policy in policies_to_restore))

            for adom in adoms_in_backup:
                print(f"\n🔄 Traitement de la restauration pour l’ADOM '{adom}'...")
                lock_adom(fmg_url, session, adom)
                print(f"🔒 ADOM '{adom}' verrouillé.")

                restore_policies(fmg_url, session, [p for p in policies_to_restore if p['adom'] == adom])
                print(f"✅ Politiques restaurées pour l’ADOM '{adom}'.")

                commit_adom(fmg_url, session, adom)
                print(f"💾 Commit effectué sur l’ADOM '{adom}'.")

                unlock_adom(fmg_url, session, adom)
                print(f"🔓 ADOM '{adom}' déverrouillé.")

            print("✅ Restauration terminée pour tous les ADOMs.")
        else:
            print("❌ Aucune politique à restaurer dans le fichier de backup.")

    fortimanager_logout(fmg_url, session)