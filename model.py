import json
import re
from langchain.chat_models import init_chat_model
from rag import search_in_rag



def model_call(model_name, message, rag=False):
    sys_prompt_SOC = 'You are part of a SOC team triaging log files. Your job is to flag logs that merit deeper investigation. Read the following logs and return: {"malicious": "True|False", "reason": "Only if malicious is true"}  Consider patterns such as failed logins, unusual access times, use of rare commands, suspicious IPs, etc. False negatives are worse than false positives in this context, but do not trigger on generic system noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders.'
    
    sys_prompt_threat_hunting = 'Act as a threat hunter analyzing a batch of logs for early indicators of compromise. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON like this: {"malicious": "True|False", "reason": "Only if malicious is true"}. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_cybersec_exp = 'You are a cybersecurity expert. You have received a batch of logs which you will analyze with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If the batch contains suspicious logs you must provide your reasoning. Output only the JSON.'
    
    sys_prompt_SOC_for_rag = 'You are part of a SOC team triaging log files. Your job is to flag logs that merit deeper investigation. Read the following logs and return: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Consider patterns such as failed logins, unusual access times, use of rare commands, suspicious IPs, etc. False negatives are worse than false positives in this context, but do not trigger on generic system noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders.'
    
    sys_prompt_threat_hunting_for_rag = 'Act as a threat hunter analyzing a batch of logs for early indicators of compromise. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON like this: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_cybersec_exp_for_rag = 'You are a cybersecurity expert. You have received a batch of logs which you will analyze with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Output only the JSON.'


    llm = init_chat_model(model_name, model_provider="ollama")

    messages = [
        # (
        #     "system",
        #     f"{sys_prompt}",
        # ),
        ("human", f"{message}\n{sys_prompt_SOC}"),
    ]
    response = llm.invoke(messages)
    #print(ai_msg.content)
    try:
        sanitized_response = response.content.replace("\n","")
        match = re.search(r'\{.*?\}', f"{sanitized_response}")
        if match:
            json_str = match.group(0)
            # print(json_str)
        else:
            raise ValueError
        json_object = json.loads(f"{json_str}")
        if rag:
            malicious = False
            if isinstance(json_object.get("malicious"), bool):
                malicious = json_object.get("malicious")
            else: 
                if json_object.get("malicious", "").lower() == "true":
                    malicious = True
            if malicious == True:
                after_rag_response, after_rag_json_object=rag_query(llm=llm, message=message, query=json_object["query"])
                if after_rag_response == -1:
                    return -1, ""
                return after_rag_response, after_rag_json_object
            else:
                return response, json_object
        return response, json_object
    except ValueError as e:
        print ("Is valid json? false")
        # print(response.content)
        print(sanitized_response)
        # print(e)
        return -1, ""
    except AttributeError as e:
        return -1, ""

def rag_query(llm, message, query):  
    sys_prompt_SOC = 'You are part of a SOC team triaging log files. Your job is to flag logs that merit deeper investigation. Read the following logs and an entry from MITRE ATT&CK database and return: {"malicious": "True|False", "reason": "Only if malicious is true"}. Consider patterns such as failed logins, unusual access times, use of rare commands, suspicious IPs, etc. False negatives are worse than false positives in this context, but do not trigger on generic system noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders.'
    
    sys_prompt_threat_hunting = 'Act as a threat hunter analyzing a batch of logs for early indicators of compromise. You have also received a possible match from MITRE ATT&CK database. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON like this: {"malicious": "True|False", "reason": "Only if malicious is true"}. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_cybersec_exp = 'You are a cybersecurity expert. You have received a batch of logs and a possible classification by MITRE ATT&CK database. You will analyze the logs with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If the batch contains suspicious logs you must provide your reasoning. Output only the JSON.'

    rag_result = search_in_rag(query=query)
    
    messages = [
        # (
        #     "system",
        #     f"{sys_prompt}",
        # ),
        ("human", f"Logs: \n{message}\nPossible MITRE ATT&CK entry: {rag_result}\n{sys_prompt_SOC}"),
    ]
    response = llm.invoke(messages)
    
    try:
        sanitized_response = response.content.replace("\n","")
        match = re.search(r'\{.*?\}', f"{sanitized_response}")
        if match:
            json_str = match.group(0)
            # print(json_str)
        else:
            raise ValueError
        json_object = json.loads(f"{json_str}")
        # print("Phase 2 response:", response.content)
        return response, json_object
    except ValueError as e:
        print ("Is valid json? false")
        # print(response.content)
        print(sanitized_response)
        # print(e)
        return -1, ""
