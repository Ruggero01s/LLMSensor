import pandas as pd
import json
file = "collected_flows/BenignTraffic.csv"

cols = ["Src IP","Src Port","Dst IP","Dst Port","Protocol",
            "Packet Length Mean", "Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Flow IAT Std", "SYN Flag Count", "RST Flag Count", 
            "Down/Up Ratio", "Idle Mean"]

df = pd.read_csv(file, usecols=cols)
df = df.sample(n=10, random_state=42)  # Randomly sample 1000 rows for testing
#df to json with one json per row
json_lines = df.to_json(orient='records', lines=True)
df_json = json_lines

json_list = json_lines.split('\n')

print(json_list[0])  # Print the first JSON object for verification

df_csv = df.to_csv()

from langchain.chat_models import init_chat_model

sys_prompt = 'You are given a batch of packet flows. Your task is to analyze them and determine if they contain malicious activity that requires further investigation. Return only a JSON response in the following format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If you find the batch suspicious, provide a brief explanation in the reason field. If not, simply return {"malicious": "False"}. Output only the JSON. Do not include any additional text or explanations outside of the JSON format.'

llm = init_chat_model("mistral-nemo:latest", model_provider="ollama")

messages = [
    # (
    #     "system",
    #     f"{sys_prompt}",
    # ),
    ("human", f"{df_json}\n{sys_prompt}"),
]
# response = llm.invoke(messages)

# print(response.content)