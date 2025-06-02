import json
import re
from langchain.chat_models import init_chat_model
from rag import search_in_rag



def model_call(model_name, message, rag, sys_prompt, sys_prompt_rag):

    llm = init_chat_model(model_name, model_provider="ollama")

    messages = [
        # (
        #     "system",
        #     f"{sys_prompt}",
        # ),
        ("human", f"{message}\n{sys_prompt}"),
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
                after_rag_response, after_rag_json_object=rag_query(llm=llm, message=message, query=json_object["query"], sys_prompt=sys_prompt_rag)
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

def rag_query(llm, message, query, sys_prompt):  
    
    rag_result = search_in_rag(query=query)
    
    messages = [
        # (
        #     "system",
        #     f"{sys_prompt}",
        # ),
        ("human", f"Logs: \n{message}\nPossible MITRE ATT&CK entry: {rag_result}\n{sys_prompt}"),
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
