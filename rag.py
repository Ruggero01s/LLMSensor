import pandas as pd
import re
from langchain_ollama import OllamaEmbeddings
from langchain.embeddings import CacheBackedEmbeddings
from langchain.storage import LocalFileStore
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
 
def read_csv(csv_file, columns):
    citation_pattern = r"\(Citation:\s*[^)]+\)"
    url_pattern = r"\(https://[^)]+\)"
    df=pd.read_csv(csv_file, usecols=columns, encoding="cp1252")
    for i, description in enumerate(df["description"]):
        new_description = description
        # Remove citations
        new_description = re.sub(citation_pattern, "", new_description)
        # Remove URLs
        new_description = re.sub(url_pattern, "", new_description)
        # Update the DataFrame
        df.loc[df.index == i, "description"] = new_description.strip()
    return df

def create_embedding(model,df):
    rag_entries = crete_entry_list(df)
    model.embed_documents(rag_entries)

def crete_entry_list(df):
    names=df["name"].tolist()
    descriptions=df["description"].tolist()
    tacticts=df["tactics"].tolist()
    detections=df["detection"].tolist()
    
    rag_entries=[]
    
    for i in range(len(names)):
        rag_entries.append(f"Name: {names[i]} | Tactics: {tacticts[i]} | Description: {descriptions[i]}")
        # rag_entries.append(f"Description: {descriptions[i]}")
    return rag_entries

def create_documents(df):
    names=df["name"].tolist()
    descriptions=df["description"].tolist()
    tacticts=df["tactics"].tolist()
    detections=df["detection"].tolist()
    
    docs=[]
    
    for i in range(len(names)):
        docs.append(Document(page_content=f"Name: {names[i]} | Tactics: {tacticts[i]} | Description: {descriptions[i]}"))
        # docs.append(Document(page_content=f"Description: {descriptions[i]}"))
    return docs

def search_in_rag(query):
    #TODO renderlo più efficiente
    csv_file = "./enterprise-attack-v17.1.csv"
    columns = ["name", "description", "tactics", "detection"]
    
    underlying_embeddings = OllamaEmbeddings(model="bge-m3")
    store = LocalFileStore("./embeddings_cache/")
    cached_embedder = CacheBackedEmbeddings.from_bytes_store(
        underlying_embeddings, store, namespace=underlying_embeddings.model
    )

    df = read_csv(csv_file=csv_file, columns=columns)

    create_embedding(cached_embedder, df)
    
    documents = create_documents(df)
    
    vector_store = FAISS.from_documents(documents, cached_embedder)
    
    results = vector_store.similarity_search(query, k=1)
    
    if not results:
        return "No matching entry found."
    result = results[0].page_content  # Get the content of the first result
    
    
    # enable if need detection append to result
    # name = result.split("|")[0].split(":")[1].strip()  # Extract the name    
    # df_filtered = df[df["name"] == name]
    # if df_filtered.empty:
    #     raise ValueError(f"No entry found for name: {name}")
    # result += df_filtered.iloc[0]["detection"]
    return result
    

if __name__ == "__main__":
    csv_file = "./enterprise-attack-v17.1.csv"
    columns = ["name", "description", "tactics", "detection"]
    
    underlying_embeddings = OllamaEmbeddings(model="bge-m3")
    store = LocalFileStore("./embeddings_cache/")
    cached_embedder = CacheBackedEmbeddings.from_bytes_store(
        underlying_embeddings, store, namespace=underlying_embeddings.model
    )

    df = read_csv(csv_file=csv_file, columns=columns)

    create_embedding(cached_embedder, df)
    
    documents = create_documents(df)
    
    vector_store = FAISS.from_documents(documents, cached_embedder)
    
    query = "The logs contain unusual and potentially malicious DNS queries. Specifically, the query for '3x6-.789-.mcAm8hmbhJguxiCi//v/4lXOltMYQr3fUQ-.SaZVEXjM*JHr390b/wFmwu2JHW7yvzztRc-.kPGx3one3pUmVwJ5W4AVrj3SbN7P*GTdlA-.mPiumN5833S6Hu8WGzWmw7Ei00j9WKxjUb-.payroll_2018.xlsx.email-19.kennedy-mendoza.info' from 10.143.0.103 to 192.168.231.254 and the subsequent reply of 195.128.194.168 indicates an attempt to resolve a highly unusual and likely obfuscated domain name, which could be indicative of phishing or other malicious activities. Additionally, the query for 'mail.smith.russellmitchell.com' forwarded to 127.0.0.1 may indicate internal DNS manipulation or potential lateral movement within the network."

    # Perform similarity search to get top k documents (e.g., k=3)
    result = search_in_rag(query=query)

    print(result)