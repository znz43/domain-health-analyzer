from utils.time import unix_to_iso



def collect_timeline(
    repo,
    domain,
    contexts,
    domain_data
):


    listing = repo.get_listing(
        domain
    )



    return {

        "is_listed": listing.get(
            "is-listed"
        ),


        "listed_date": unix_to_iso(
            listing.get(
                "ts"
            )
        ),


        "listed_until": unix_to_iso(
            listing.get(
                "listed-until"
            )
        ),


        "last_seen": domain_data.get(
            "last_seen"
        ),



    }