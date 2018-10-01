# authorized-dns-keys

Small helper tool primarily meant to be invoked by OpenSSH's
`AuthorizedKeysCommand` in environments that already use
[Hesiod](https://en.wikipedia.org/wiki/Hesiod_\(name_service\)). It queries,
sorts, concatenates and eventually prints SSH public keys found in DNS TXT
records.

It also does the inverse and can create BIND style DNS record entries. Records
live in `$user.ssh$lhs$rhs` and look like this:

    user.ssh.ns.example.org. TXT "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCutHjcbooZDl+4jpsGMC7JewGXTgULjWuSMMzpM0hCKn4aIOaULkbDV020NiO+dfo0DTo2vXwZn6GqUu4xyZVk5dQa+yk6He3DAzgwsXxsLuwQYfGI0xVgGsaBFWPXqXjWIq6amKKG6o2Ll15HOw6Tj0MULGqQtC/j00VrKxNztNy2Lesa06KkKnFBFimA29ZhVlUjm8W/t7rwg0alulLnoOp" "ch9qbE/3yO3KOdNqCdDwNoRImAQk6KRlpWSr9ZHB4YnjQNNZCJ+yjC/KdqQ1awdKWTOMz2jfbhd/WHeH7XRY4iU2ZatVj6ZAcaqKvkaG8mWDYq2RNf6k88FgLdM33 user@host"
                             TXT "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHz4HTq0S77shqWG1tfc8EHSSMg+unYB+uUZaKiUcq1N user@host"

Requires a `/etc/hesiod.conf` configuration file.

### Isn't this kind of pointless as the same can be achieved with `AuthorizedKeysCommand /usr/bin/hesinfo %u ssh`?

Yes, however I initially misremembered how TXT records work, and I wanted to
learn about Rust and this was a simple enough project to try, so 🤷‍♂️
