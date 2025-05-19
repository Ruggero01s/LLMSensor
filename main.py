from datetime import timedelta, datetime
from prepocessing import prepare_batches, Batch
from model import model_call


def minute_range(start_datetime: datetime, end_datetime: datetime, step_minutes: int):
    total_minutes = int((end_datetime - start_datetime).total_seconds() / 60)
    for n in range(1, total_minutes + 1, step_minutes):
        yield start_datetime + timedelta(minutes=n)


if __name__ == "__main__":
    start_time = datetime(2022, 1, 21, 0, 0, 0, 0)
    end_time = datetime(2022, 1, 25, 0, 0, 0, 0)
    
    
    step_minutes=10
    overlap_minutes=1
    max_batch_size=10
    dt2 = datetime(2022, 1, 23, 11, 20, 0, 0)
    model_output=[()]
    # for current_time in minute_range(start_time, end_time, step_minutes):
    #     batch_list=prepare_batches(current_time,step_minutes+overlap_minutes,max_batch_size,True)
        # for batch in batch_list:
        #     response=model_call("llama3.1",batch.get_batch_as_string())
        #     model_output.append((batch,response))
    batches = prepare_batches(dt2,10,10,True)
    print("Finished batching")
    response=model_call("llama3.1",batches[0].get_batch_as_string())
    print(response.content)



    
