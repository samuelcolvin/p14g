import logfire

# spans are made but go nowhere; without this, logfire warns on the first one and the warning is an error
logfire.configure(send_to_logfire=False, console=False)
