# App config
# TODO: Change to meet your needs. Any email related feature needs an update of this file and without updating to your
#  needs, functionality of the project might be compromised.
class Config(object):
    DEBUG = False
    SESSION_PERMANENT = False
    SESSION_TYPE = "filesystem"
    SESSION_COOKIE_PERMANENT = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Setup email sending
    MAIL_SERVER = ""  # TODO: Add SMTP server
    MAIL_PORT = 465
    MAIL_USERNAME = ""  # TODO: Add email address
    MAIL_PASSWORD = ""  # TODO: Add email password
    MAIL_USE_SSL = True
    MAIL_DEFAULT_SENDER = ""  # TODO: Add email address

    DB_NAME = "database.db"

    SECRET_KEY = "b\"\xf5;\xb7\x92\x1f'\xacvT\xf5\xe5x6\xb2\xc4\xe4\""
    EMAIL_CONFIRMATION_SALT = \
        "sjqcSz dv0&!w^~ul7T*)@)6XY=_n0J&N4Q(CQ.8?? .&.pzy/qoa_?+nKfdv*HOE)\"rJi_E/;-uN+x*:ER(0UaIS=Re@ l_2M_q"
    CHANGE_EMAIL_SALT = \
        ")ed/e@?W3.(/DDc$9N`90z\"ZMizF d>%@T1zVM7LGM_m=bJw!3eJ@Ws@n=43$O2*u^K_^:EW},SY*p.\"LcP&\"!CPNO+f)M?3oH*g"
    RESET_PASSWORD_SALT = \
        "G6^_M6&\\$Ho;TO]~]hFg--! pqj(yu)Mn~K,WCLRiv0XF_7O.GXG#\"S/_:O^{W:*$P#x|RW?*xljo*k[}2*=`\'?%R>\'z!f-y&\\.6"
