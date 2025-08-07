import json

def lambda_handler(event, context):
    hello_world_ascii = """
    <pre>
                                                                                                                                                                                           dddddddd
      HHHHHHHHH     HHHHHHHHH                    lllllll lllllll                       WWWWWWWW                           WWWWWWWW                                     lllllll             d::::::d
      H:::::::H     H:::::::H                    l:::::l l:::::l                       W::::::W                           W::::::W                                     l:::::l             d::::::d
      H:::::::H     H:::::::H                    l:::::l l:::::l                       W::::::W                           W::::::W                                     l:::::l             d::::::d
      HH::::::H     H::::::HH                    l:::::l l:::::l                       W::::::W                           W::::::W                                     l:::::l             d:::::d 
        H:::::H     H:::::H      eeeeeeeeeeee     l::::l  l::::l    ooooooooooo         W:::::W           WWWWW           W:::::W    ooooooooooo   rrrrr   rrrrrrrrr    l::::l     ddddddddd:::::d 
        H:::::H     H:::::H    ee::::::::::::ee   l::::l  l::::l  oo:::::::::::oo        W:::::W         W:::::W         W:::::W   oo:::::::::::oo r::::rrr:::::::::r   l::::l   dd::::::::::::::d 
        H::::::HHHHH::::::H   e::::::eeeee:::::ee l::::l  l::::l o:::::::::::::::o        W:::::W       W:::::::W       W:::::W   o:::::::::::::::or:::::::::::::::::r  l::::l  d::::::::::::::::d 
        H:::::::::::::::::H  e::::::e     e:::::e l::::l  l::::l o:::::ooooo:::::o         W:::::W     W:::::::::W     W:::::W    o:::::ooooo:::::orr::::::rrrrr::::::r l::::l d:::::::ddddd:::::d 
        H:::::::::::::::::H  e:::::::eeeee::::::e l::::l  l::::l o::::o     o::::o          W:::::W   W:::::W:::::W   W:::::W     o::::o     o::::o r:::::r     r:::::r l::::l d::::::d    d:::::d 
        H::::::HHHHH::::::H  e:::::::::::::::::e  l::::l  l::::l o::::o     o::::o           W:::::W W:::::W W:::::W W:::::W      o::::o     o::::o r:::::r     rrrrrrr l::::l d:::::d     d:::::d 
        H:::::H     H:::::H  e::::::eeeeeeeeeee   l::::l  l::::l o::::o     o::::o            W:::::W:::::W   W:::::W:::::W       o::::o     o::::o r:::::r             l::::l d:::::d     d:::::d 
        H:::::H     H:::::H  e:::::::e            l::::l  l::::l o::::o     o::::o             W:::::::::W     W:::::::::W        o::::o     o::::o r:::::r             l::::l d:::::d     d:::::d 
      HH::::::H     H::::::HHe::::::::e          l::::::ll::::::lo:::::ooooo:::::o              W:::::::W       W:::::::W         o:::::ooooo:::::o r:::::r            l::::::ld::::::ddddd::::::dd
      H:::::::H     H:::::::H e::::::::eeeeeeee  l::::::ll::::::lo:::::::::::::::o               W:::::W         W:::::W          o:::::::::::::::o r:::::r            l::::::l d:::::::::::::::::d
      H:::::::H     H:::::::H  ee:::::::::::::e  l::::::ll::::::l oo:::::::::::oo                 W:::W           W:::W            oo:::::::::::oo  r:::::r            l::::::l  d:::::::::ddd::::d
      HHHHHHHHH     HHHHHHHHH    eeeeeeeeeeeeee  llllllllllllllll   ooooooooooo                    WWW             WWW               ooooooooooo    rrrrrrr            llllllll   ddddddddd   ddddd
    </pre>
    """
    html_content = f"""
    <html>
      <head><title>Hello World</title></head>
      <body>
        {hello_world_ascii}
      </body>
    </html>
    """
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html',
        },
        'body': html_content
    }

