
from langchain.chat_models import init_chat_model



def model_call(model_name, message):

    sys_prompt = "You are a cybersecurity expert. You will receive a batch of logs. You will analyze this batch and return a ruling about whether the logs contain malicious activity or not. If you suspect malicious activity explain your ruling. Your output must be in JSON with the following format: '{ malicious: True | False, reason: Your explanation here, only if malicious is True}'"

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
    return response 
    