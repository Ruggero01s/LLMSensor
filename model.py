import json
import re
from langchain.chat_models import init_chat_model
from rag import search_in_rag



def model_call(model_name, message):

    # sys_prompt = 'You are a cybersecurity expert. You will receive a batch of logs. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you suspect malicious activity explain your ruling. Your output must be in JSON with the following format: {"malicious" : "True | False", "reason" : "Your explanation here, only if malicious is True"}. Output must be only the JSON file with the requested features. No other output will be tolerated.'
    # sys_prompt = 'You are a cybersecurity expert. You will receive a batch of logs extracted from normal operations of an enterprise. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you find malicious activity you must provide proof, otherwise do not. Your output must be in JSON: In the case of malicious activity detected you will use the following format: {"malicious" : "True", "reason" : "Your explanation and proof here"}; otherwise you will use the format: {"malicious" : "False", "reason" : ""} Output must be only the JSON file with the requested features. No other output will be tolerated.'
    sys_prompt = 'You are a cybersecurity expert. Above you have received a batch of logs extracted from normal operations of an enterprise. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you find malicious activity you must provide proof, otherwise do not. Your output must be in JSON: In the case of malicious activity detected you will use the following format: {"malicious" : "True", "rag_query" : "Query to a rag system"}; otherwise you will use the format: {"malicious" : "False", "reason" : "Your reason"}. The query should be a concise but specific and meaningful description of the logs in the batch. Output must be only the JSON file with the requested features. No other output will be tolerated.'

    
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
        if json_object.get("malicious", "").lower() == "true":
            # print("Query:", json_object["rag_query"])
            after_rag_response, after_rag_json_object=rag_query(llm=llm, message=message, query=json_object["rag_query"])
            if after_rag_response == -1:
                return -1, ""
            return after_rag_response, after_rag_json_object
        else:
            return response, json_object
    except ValueError as e:
        print ("Is valid json? false")
        # print(response.content)
        print(sanitized_response)
        # print(e)
        return -1, ""

def rag_query(llm, message, query):
    # sys_prompt = 'You are a cybersecurity expert. Above you have received a batch of logs extracted from normal operations of an enterprise and a rag query result based on a description of the logs. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you find malicious activity you must provide proof, otherwise do not. Your output must be in JSON: In the case of malicious activity detected you will use the following format: {"malicious" : "True", "reason" : "Your explanation and proof here"}; otherwise you will use the format: {"malicious" : "False", "reason" : ""}. Output must be only the JSON file with the requested features. No other output will be tolerated.'
    sys_prompt = 'You are a cybersecurity expert. Above you have received a batch of logs extracted from normal operations of an enterprise and a rag query result based on a description of the logs. You have already analyzed this batch and deemed it malicious. You will analyze this batch again with the added context of the rag retrieval and return a ruling about whether the logs contain malicious activity or not. If you find malicious activity you must provide proof, otherwise provide your reason for changing idea. Your output must be in JSON: In the case of malicious activity detected you will use the following format: {"malicious" : "True", "reason" : "Your explanation and proof here"}; otherwise you will use the format: {"malicious" : "False", "reason" : "Reason fro changing your mind"}. Output must be only the JSON file with the requested features. No other output will be tolerated.'

    rag_result = search_in_rag(query=query)
    
    messages = [
        # (
        #     "system",
        #     f"{sys_prompt}",
        # ),
        ("human", f"Logs: \n{message}\nRag retrieved block: {rag_result}\n{sys_prompt}"),
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
