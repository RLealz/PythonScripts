from telethon import TelegramClient, sync

# Prompt the user for their api_id and api_hash
api_id = input("Enter your api_id: ")
api_hash = input("Enter your api_hash: ")

# Prompt the user for the channel link or username
channel_link = input("Enter the channel link or username: ")

client = TelegramClient('id', api_id, api_hash)
client.start()

entity = client.get_entity(channel_link)

# Get the channel name from the channel link or username
if channel_link.startswith('https://t.me/'):
    channel_name = channel_link.split('/')[-1]
elif channel_link.startswith('@'):
    channel_name = channel_link[1:]
else:
    channel_name = 'unknown_channel'

# Format the output
formatted_output = f"""Channel Information:
- ID: {entity.id}
- Title: {entity.title}
- Username: {entity.username}
- Date Created: {entity.date}
- Broadcast: {entity.broadcast}
- Verified: {entity.verified}
- Megagroup: {entity.megagroup}
- Restricted: {entity.restricted}
- Slowmode Enabled: {entity.slowmode_enabled}
- Access Hash: {entity.access_hash}
"""

# Ask the user if they want to output the result to a file or display it on the screen
output_option = input("Do you want to output the result to a file or display it on the screen? (Enter 'file' or 'screen'): ")

if output_option.lower() == 'file':
    # Write the formatted output to a text file with utf-8 encoding
    output_file_name = f'{channel_name}.txt'
    with open(output_file_name, 'w', encoding='utf-8') as file:
        file.write(formatted_output)
    print(f"The result has been written to {output_file_name}.")
else:
    # Display the formatted output on the screen
    print(formatted_output)