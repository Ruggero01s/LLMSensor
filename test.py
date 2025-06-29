

from langchain.chat_models import init_chat_model

prompt = 'You are a system analyst. Please create realistic logs coming from a system. This should be logs such as authentication logs, system logs, dns logs, etc. The message should be a realistic log message. Please generate a sequence of logs.'

# llm = init_chat_model("mistral-nemo:latest", model_provider="ollama")
# llm = init_chat_model("qwen2.5-coder:14b", model_provider="ollama")
llm = init_chat_model("gemma3:12b", model_provider="ollama")
# llm = init_chat_model("llama3.1:8b", model_provider="ollama")


messages = [
    # (
    #     "system",
    #     f"{sys_prompt}",
    # ),
    ("human", f"\n{prompt}"),
]
response = llm.invoke(messages)

print(response.content)