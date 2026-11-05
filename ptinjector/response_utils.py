def get_response_chain(response):
    if response is None:
        return []

    history = getattr(response, "history", [])


    return list(history) + [response]