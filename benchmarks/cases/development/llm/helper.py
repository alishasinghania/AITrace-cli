"""Cross-file helper that forwards a request payload to an LLM."""


def run_llm(user_message):
    return llm.invoke(user_message)  # gt:FLOW-LLM:confirmed_taint
