# flask_API_simple_exemple
Some simple flask exemple using API

vscode launch.json for debuggin

for testing I used https://dreamstop.com/wp-content/uploads/2015/10/zebra-dream.jpg

{
    "configurations": [
        {
            "name": "Python: Remote Attach",
            "type": "python",
            "request": "attach",
            "port": 10001,
            "host": "0.0.0.0",
            "pathMappings": [
            {
                "localRoot": "${workspaceFolder}/web",
                "remoteRoot":  "/web"
            }
            ]
        }
    ]
}