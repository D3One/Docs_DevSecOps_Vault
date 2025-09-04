package main

deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value
    contains(val[_], "latest")
    msg = "Do not use the 'latest' tag. Use a specific versioned tag."
}

deny[msg] {
    not user_exists
    msg = "Dockerfile must specify a non-root user with the USER instruction."
}

user_exists {
    input[i].Cmd == "user"
}
