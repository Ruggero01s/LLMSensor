import json
from langchain.chat_models import init_chat_model



def model_call(model_name, message):

    # sys_prompt = 'You are a cybersecurity expert. You will receive a batch of logs. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you suspect malicious activity explain your ruling. Your output must be in JSON with the following format: {"malicious" : "True | False", "reason" : "Your explanation here, only if malicious is True"}. Output must be only the JSON file with the requested features. No other output will be tolerated.'
    sys_prompt = 'You are a cybersecurity expert. You will receive a batch of logs extracted from normal operations of an enterprise. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you find malicious activity you must provide proof, otherwise do not. Your output must be in JSON: In the case of malicoius activity detected you will use the following format: {"malicious" : "True", "reason" : "Your explanation and proof here"}; otherwise you will use the format: {"malicious" : "False", "reason" : ""} Output must be only the JSON file with the requested features. No other output will be tolerated.'

    llm = init_chat_model(model_name, model_provider="ollama")

    messages = [
        (
            "system",
            f"{sys_prompt}",
        ),
        ("human", f"{message}"),
    ]
    response = llm.invoke(messages)
    #print(ai_msg.content)
    try:
        json_object = json.loads(rf"{response.content}")
        return response, json_object
    except ValueError as e:
        print ("Is valid json? false")
        print(response.content)

    