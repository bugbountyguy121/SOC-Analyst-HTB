---
title: "SIEM Visualization Example 1: Failed Logon Attempts (All Users) | Hack The Box Academy"
source: ""
exported: "2026-10-09T14:39:02.659Z"
tags: [htb, academy]
---
# SIEM Visualization Example 1: Failed Logon Attempts (All Users) | Hack The Box Academy

Source: 
Exported: 2026-10-09T14:39:02.659Z
Pages exported: 9

# SIEM Visualization Example 1: Failed Logon Attempts (All Users)

Source: https://academy.hackthebox.com/app/module/211/section/2255

# SIEM Visualization Example 1: Failed Logon Attempts (All Users)

Dashboards in SIEM solutions serve as containers for multiple visualizations, allowing us to organize and display data in a meaningful way.

In this and the following sections, we will create a dashboard and some visualizations from scratch.

* * *

## Developing Our First Dashboard & Visualization

Navigate to the bottom of this section and click on `Click here to spawn the target system!`

Now, navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

Delete the existing "SOC-Alerts" dashboard as follows.

![Elastic dashboard interface showing 'SOC-Alerts' with options to delete or create a dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization29.png)

When visiting the Dashboard page again we will be presented with a message indicating that no dashboards currently exist. Additionally, there will be an option available to create a new Dashboard and its first visualization. To initiate the creation of our first dashboard, we simply have to click on the "Create new dashboard" button.

![Elastic interface prompting to create the first dashboard with options to install sample data and create a new dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/dashboard.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

![Elastic interface for editing a new dashboard, prompting to add the first visualization with options to create or add from library.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization.png)

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

Before proceeding with any configuration, it is important for us to first click on the calendar icon to open the time picker. Then, we need to specify the date range as "last 15 years". Finally, we can click on the "Apply" button to apply the specified date range to the data.

![Elastic dashboard creation interface with options to add filter, select index pattern 'windows*', search field names, and choose 'Bar vertical stacked' visualization.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization1.png)

There are four things for us to notice on this window:

1.  A filter option that allows us to filter the data before creating a graph. For example, if our goal is to display failed logon attempts, we can use a filter to only consider event IDs that match `4625 – Failed logon attempt on a Windows system`. The following image demonstrates how we can specify such a filter.  
    ![Elastic dashboard interface with 'Add filter' option open, setting filter for 'event.code' to '4625' using operator 'is'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization2.png)
2.  This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
3.  This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. For example, let's say we are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.  
    ![Elastic dashboard interface with a filter for 'event.code: 4625' and search for fields starting with 'user.' showing available fields like 'user.name.keyword'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization11.png)  
    "Why `user.name.keyword` and not `user.name`?", you may ask. We should use the `.keyword` field when it comes to aggregations. Please refer to this [stackoverflow question](https://stackoverflow.com/questions/48869795/difference-between-a-field-and-the-field-keyword) for a more elaborate answer.
4.  Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.  
    ![Elastic interface showing visualization type options with 'Bar vertical stacked' selected, including other options like 'Metric' and 'Table'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization4.png)

* * *

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Elastic table configuration interface with options to add or drag-and-drop fields for rows, columns, and metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked by count of records in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization6.png)

**Note**: You will notice `Rank by Alphabetical` and not `Rank by Count of records` like in the screenshot above. This is OK. By the time you perform the next configuration below, `Count of records` will become available.

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Elastic table configuration showing 'windows*' index pattern, with 'Top values of user.name.keyword' in rows, and options to add fields to columns and metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Elastic metrics configuration interface showing quick functions like Average, Count, and Sum, with 'Count' selected.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization8.png)

As soon as we select "Count" as the metric, we will observe that the table gets populated with data (assuming that there are events present in the selected data set)

![Elastic table showing top values of 'user.name.keyword' with counts, and metrics configuration set to 'Count' for records.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization9.png)

One final addition to the table is to include another "Rows" setting to show the machine where the failed logon attempt occurred. To do this, we will select the `host.hostname.keyword` field, which represents the computer reporting the failed logon attempt. This will allow us to display the hostname or machine name alongside the count of failed logon attempts, as shown in the image.

![Elastic table showing top values of 'user.name.keyword' and 'host.hostname.keyword' with record counts, configured in rows.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization12.png)

Now we can see three columns in the table, which contain the following information:

1.  The username of the individuals logging in (Note: It currently displays both users and computers. Ideally, a filter should be implemented to exclude computer devices and only display users).
2.  The machine on which the logon attempt occurred.
3.  The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard, appearing as shown in the following image.

![Elastic dashboard showing a table with top values of user names and hostnames, and their record counts.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization13.png)

Let's not forget to save the dashboard as well. We can do so by simply clicking on the "Save" button.

![Elastic interface showing 'Save dashboard' dialog with title 'SOC-Alerts', description for HTB Academy's SOC Analyst Job-Role Path, and option to store time with dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization15.png)

* * *

## Refining The Visualization

Suppose the SOC Manager suggested the following refinements:

-   Clearer column names should be specified in the visualization
-   The Logon Type should be included in the visualization
-   The results in the visualization should be sorted
-   The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames should not be monitored
-   [Computer accounts](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-computer) should not be monitored (not a good practice)

Let's refine the visualization we created, so that it fulfills the suggestions above.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

The dashboard we previously created should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard interface showing a list with 'SOC-Alerts' and options to create or edit a dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization16.png)

Let's now click on the "gear" button at the upper-right corner of our visualization, and then click on "Edit lens".

![Elastic dashboard editing 'SOC-Alerts' with a table of top user and hostnames, and options to edit lens, clone panel, or edit panel title.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization18.png)

"Top values of user.name.keyword" should be changed as follows.

![Elastic table configuration with 'Top values of user.name.keyword' and 'host.hostname.keyword' in rows, and 'Count of records' in metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization19.png)

![Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked alphabetically in ascending order, with display name 'Username'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization17.png)

"Top values of host.hostname.keyword" should be changed as follows.

![Elastic interface for configuring rows, selecting 'host.hostname.keyword' field, displaying top 1000 values, ranked by count of records in descending order, with display name 'Event logged by'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization20.png)

The "Logon Type" can be added as follows (we will use the `winlog.logon.type.keyword` field).

![Elastic table configuration with 'Top values of user.name.keyword' and 'Event logged by' in rows, and 'Count of records' in metrics, with option to add fields.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization21.png)![Rows configuration panel with 'winlog.logon.type.keyword' field selected, number of values set to 1000, ranked by count of records in descending order, display name 'Logon Type'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization22.png)

"Count of records" should be changed as follows. ![Metrics panel with 'Count' function selected, field set to 'Records', display name '# of logins', text alignment 'Right'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization23.png)

We can introduce result sorting as follows. ![Elastic dashboard showing a table with columns: Username, Event logged by, Logon Type, and '# of logins' sorted descending.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization25.png)

All we have to do now is click on "Save and return".

The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames can be excluded by specifying additional filters as follows.

![Elastic dashboard with filter settings: Field 'user.name.keyword', operator 'is not', value 'DESKTOP-DPOESND'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization24.png)

Computer accounts can be excluded by specifying the following KQL query and clicking on the "Update" button.

        shellsession
`NOT user.name: *$ AND winlog.channel.keyword: Security`

The `AND winlog.channel.keyword: Security` part is to ensure that no unrelated logs are accounted for.

![Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization34.png)

This is our visualization after all the refinements we performed.

![Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, displaying a table with columns: Username, Event logged by, Logon Type, and '# of logins'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization35.png)

Finally, let's give our visualization a title by clicking on "No Title".

![Elastic dashboard with filters applied, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'. Customize panel dialog open with 'Show panel title' option.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization36.png)

Don't forget to click on the "Save" button (the one on the upper-right hand side of the window).

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.

---

# ==🟡SIEM Visualization Example 1: Failed Logon Attempts (All Users)==

Source: https://academy.hackthebox.com/app/module/211/section/2274

# SIEM Visualization Example 1: Failed Logon Attempts (All Users)

Dashboards in SIEM solutions serve as containers for multiple visualizations, allowing us to organize and display data in a meaningful way.

In this and the following sections, we will create a dashboard and some visualizations from scratch.

* * *

## Developing Our First Dashboard & Visualization

Navigate to the bottom of this section and click on `Click here to spawn the target system!`

Now, navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

Delete the existing "SOC-Alerts" dashboard as follows.

![Elastic dashboard interface showing 'SOC-Alerts' with options to delete or create a dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization29.png)

When visiting the Dashboard page again we will be presented with a message indicating that no dashboards currently exist. Additionally, there will be an option available to create a new Dashboard and its first visualization. To initiate the creation of our first dashboard, we simply have to click on the "Create new dashboard" button.

![Elastic interface prompting to create the first dashboard with options to install sample data and create a new dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/dashboard.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

![Elastic interface for editing a new dashboard, prompting to add the first visualization with options to create or add from library.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization.png)

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

Before proceeding with any configuration, it is important for us to first click on the calendar icon to open the time picker. Then, we need to specify the date range as "last 15 years". Finally, we can click on the "Apply" button to apply the specified date range to the data.

![Elastic dashboard creation interface with options to add filter, select index pattern 'windows*', search field names, and choose 'Bar vertical stacked' visualization.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization1.png)

There are four things for us to notice on this window:

1.  A filter option that allows us to filter the data before creating a graph. For example, if our goal is to display failed logon attempts, we can use a filter to only consider event IDs that match `4625 – Failed logon attempt on a Windows system`. The following image demonstrates how we can specify such a filter.  
    ![Elastic dashboard interface with 'Add filter' option open, setting filter for 'event.code' to '4625' using operator 'is'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization2.png)
2.  This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
3.  This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. For example, let's say we are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.  
    ![Elastic dashboard interface with a filter for 'event.code: 4625' and search for fields starting with 'user.' showing available fields like 'user.name.keyword'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization11.png)  
    "Why `user.name.keyword` and not `user.name`?", you may ask. We should use the `.keyword` field when it comes to aggregations. Please refer to this [stackoverflow question](https://stackoverflow.com/questions/48869795/difference-between-a-field-and-the-field-keyword) for a more elaborate answer.
4.  Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.  
    ![Elastic interface showing visualization type options with 'Bar vertical stacked' selected, including other options like 'Metric' and 'Table'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization4.png)

* * *

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Elastic table configuration interface with options to add or drag-and-drop fields for rows, columns, and metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked by count of records in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization6.png)

**Note**: You will notice `Rank by Alphabetical` and not `Rank by Count of records` like in the screenshot above. This is OK. By the time you perform the next configuration below, `Count of records` will become available.

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Elastic table configuration showing 'windows*' index pattern, with 'Top values of user.name.keyword' in rows, and options to add fields to columns and metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Elastic metrics configuration interface showing quick functions like Average, Count, and Sum, with 'Count' selected.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization8.png)

As soon as we select "Count" as the metric, we will observe that the table gets populated with data (assuming that there are events present in the selected data set)

![Elastic table showing top values of 'user.name.keyword' with counts, and metrics configuration set to 'Count' for records.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization9.png)

One final addition to the table is to include another "Rows" setting to show the machine where the failed logon attempt occurred. To do this, we will select the `host.hostname.keyword` field, which represents the computer reporting the failed logon attempt. This will allow us to display the hostname or machine name alongside the count of failed logon attempts, as shown in the image.

![Elastic table showing top values of 'user.name.keyword' and 'host.hostname.keyword' with record counts, configured in rows.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization12.png)

Now we can see three columns in the table, which contain the following information:

1.  The username of the individuals logging in (Note: It currently displays both users and computers. Ideally, a filter should be implemented to exclude computer devices and only display users).
2.  The machine on which the logon attempt occurred.
3.  The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard, appearing as shown in the following image.

![Elastic dashboard showing a table with top values of user names and hostnames, and their record counts.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization13.png)

Let's not forget to save the dashboard as well. We can do so by simply clicking on the "Save" button.

![Elastic interface showing 'Save dashboard' dialog with title 'SOC-Alerts', description for HTB Academy's SOC Analyst Job-Role Path, and option to store time with dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization15.png)

* * *

## Refining The Visualization

Suppose the SOC Manager suggested the following refinements:

-   Clearer column names should be specified in the visualization
-   The Logon Type should be included in the visualization
-   The results in the visualization should be sorted
-   The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames should not be monitored
-   [Computer accounts](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-computer) should not be monitored (not a good practice)

Let's refine the visualization we created, so that it fulfills the suggestions above.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

The dashboard we previously created should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard interface showing a list with 'SOC-Alerts' and options to create or edit a dashboard.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization16.png)

Let's now click on the "gear" button at the upper-right corner of our visualization, and then click on "Edit lens".

![Elastic dashboard editing 'SOC-Alerts' with a table of top user and hostnames, and options to edit lens, clone panel, or edit panel title.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization18.png)

"Top values of user.name.keyword" should be changed as follows.

![Elastic table configuration with 'Top values of user.name.keyword' and 'host.hostname.keyword' in rows, and 'Count of records' in metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization19.png)

![Elastic interface for configuring rows, selecting 'user.name.keyword' field, displaying top 1000 values, ranked alphabetically in ascending order, with display name 'Username'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization17.png)

"Top values of host.hostname.keyword" should be changed as follows.

![Elastic interface for configuring rows, selecting 'host.hostname.keyword' field, displaying top 1000 values, ranked by count of records in descending order, with display name 'Event logged by'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization20.png)

The "Logon Type" can be added as follows (we will use the `winlog.logon.type.keyword` field).

![Elastic table configuration with 'Top values of user.name.keyword' and 'Event logged by' in rows, and 'Count of records' in metrics, with option to add fields.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization21.png)![Rows configuration panel with 'winlog.logon.type.keyword' field selected, number of values set to 1000, ranked by count of records in descending order, display name 'Logon Type'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization22.png)

"Count of records" should be changed as follows. ![Metrics panel with 'Count' function selected, field set to 'Records', display name '# of logins', text alignment 'Right'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization23.png)

We can introduce result sorting as follows. ![Elastic dashboard showing a table with columns: Username, Event logged by, Logon Type, and '# of logins' sorted descending.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization25.png)

All we have to do now is click on "Save and return".

The DESKTOP-DPOESND, WIN-OK9BH1BCKSD, and WIN-RMMGJA7T9TC usernames can be excluded by specifying additional filters as follows.

![Elastic dashboard with filter settings: Field 'user.name.keyword', operator 'is not', value 'DESKTOP-DPOESND'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization24.png)

Computer accounts can be excluded by specifying the following KQL query and clicking on the "Update" button.

        shellsession
`NOT user.name: *$ AND winlog.channel.keyword: Security`

The `AND winlog.channel.keyword: Security` part is to ensure that no unrelated logs are accounted for.

![Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization34.png)

This is our visualization after all the refinements we performed.

![Elastic dashboard with filters: NOT user.name:*$ AND winlog.channel.keyword: Security, displaying a table with columns: Username, Event logged by, Logon Type, and '# of logins'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization35.png)

Finally, let's give our visualization a title by clicking on "No Title".

![Elastic dashboard with filters applied, showing a table with columns: Username, Event logged by, Logon Type, and '# of logins'. Customize panel dialog open with 'Show panel title' option.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization36.png)

Don't forget to click on the "Save" button (the one on the upper-right hand side of the window).

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.

---

# SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)

Source: https://academy.hackthebox.com/app/module/211/section/2274

# SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)

In this SIEM visualization example we want to create visualization to monitor failed login attempts against disabled users.

We mention "failed" because it is not possible to log in with a disabled user, so it will never be successful even if the correct credentials are provided. In a scenario where the correct credentials are provided, the Windows logs will contain an additional SubStatus value of 0xC0000072, that indicates the reason of the failure.

Navigate to the bottom of this section and click on `Click here to spawn the target system!`.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard interface displaying a list of dashboards. The screen shows a single dashboard titled 'SOC-Alerts' with an edit icon highlighted. A 'Create dashboard' button is visible.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization16.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

![Elastic dashboard interface with highlighted elements: 'Add filter' button, filter selection ('windows*'), search field for field names, and 'Bar vertical stacked' chart type.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization1.png)

There are four things for us to notice on this window:

1.  A filter option that allows us to filter the data before creating a graph. In this case our goal is to display failed logon attempts against disabled users only. We can use a filter to only consider event IDs that match `4625 – Failed logon attempt on a Windows system`, like we did in the previous visualization example. In this case though, we should also take into account the SubStatus (`winlog.event_data.SubStatus` field) that indicates, when set to 0xC0000072, that the failure is due to a logon with disabled user. The following image demonstrates how we can specify such a filter.  
    ![Elastic dashboard with an active filter: 'event.code: 4625' and 'winlog.event_data.SubStatus: 0xc0000072'. Edit filter panel shows 'winlog.event_data.SubStatus' field set to '0xc0000072' (Disabled user) with operator 'is'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization30.png)
2.  This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
3.  This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. Like in the previous visualization, we are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.  
    ![Elastic dashboard search interface showing a query for 'user.' with available fields like related.user.keyword and user.name.keyword.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization11.png)
4.  Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.  
    ![Visualization type menu in Elastic showing options like Metric, Table, Bar horizontal, and Bar vertical stacked.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization4.png)

* * *

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Elastic table configuration interface with options to add or drag-and-drop fields into Rows, Columns, and Metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Elastic Rows configuration for user.name.keyword, showing top 1000 values ranked by count of records in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization6.png)

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Elastic table configuration with 'Top values of user.name.keyword' in Rows and options to add fields in Columns and Metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Elastic Metrics configuration with 'Count' function selected from options like Average, Median, and Sum.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization8.png)

One final addition to the table is to include another "Rows" setting to show the machine where the failed logon attempt occurred. To do this, we will select the `host.hostname.keyword` field, which represents the computer reporting the failed logon attempt. This will allow us to display the hostname or machine name alongside the count of failed logon attempts, as shown in the image.

![Elastic table showing top values of user.name.keyword as 'anni' and host.hostname.keyword as 'WS001' with a count of records as 1.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization31.png)

Now we can see three columns in the table, which contain the following information:

1.  The disabled user whose credentials generated the failed logon attempt event.
2.  The machine on which the logon attempt occurred.
3.  The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard.

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.

---

# ==🟡SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts==

Source: https://academy.hackthebox.com/app/module/211/section/2276

# SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts

In this SIEM visualization example, we aim to create a visualization to monitor successful RDP logons specifically related to service accounts. Service account credentials are never used for RDP logons in corporate/real-world environments. We have been informed by the IT Operations department that all service accounts on the environment start with `svc-`.

The motivation for this visualization stems from the fact that service accounts often possess exceptionally high privileges. We need to keep a close eye on how service accounts are used.

Our visualization will be based on the following Windows event log.

-   [4624: An account was successfully logged on](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)

Navigate to the bottom of this section and click on `Click here to spawn the target system!`.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

![Elastic Dashboards page with a 'Create dashboard' button, search bar, and a listed dashboard titled 'SOC-Alerts' with an edit option.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization16.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

![Elastic dashboard interface with options to add a filter, select 'windows*' index, search field names, and choose 'Bar vertical stacked' visualization.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization1.png)

There are four things for us to notice on this window:

1.  A filter option that allows us to filter the data before creating a graph. In this case our goal is to display successful RDP logons specifically related to service accounts. We can use a filter to only consider event IDs that match `4624 – An account was successfully logged on`. In this case though, we should also take into account the logon type which should be `RemoteInteractive` (`winlog.logon.type` field). The following images demonstrates how we can specify such filters.  
    ![Elastic filter editor with 'event.code' set to 'is 4624' and options to save or cancel.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization38.png)  
    ![Elastic filter editor with 'winlog.logon.type' set to 'is RemoteInteractive' and options to save or cancel.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization39.png)
2.  This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
3.  This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. We are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.  
    ![Elastic search interface with query 'user.' and available fields like related.user.keyword and user.name.keyword.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization11.png)
4.  Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.  
    ![Elastic visualization type menu with options like Metric, Table, Bar horizontal, and Bar vertical stacked.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization4.png)

* * *

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Table configuration interface with options to add or drag-and-drop fields into Rows, Columns, and Metrics sections.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Rows configuration interface: Select user.name.keyword field, top 1000 values, ranked by count of records in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization6.png)

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Table configuration: Rows set to top values of user.name.keyword, add fields to Columns and Metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Metrics selection interface: Choose 'Count' function for field.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization8.png)

One final addition to the table is to include two more "Rows" settings to show the machine where the successful RDP logon attempt occurred and the machine that initiated the successful RDP logon attempt. To do this, we will select the `host.hostname.keyword` field that represents the computer reporting the successful RDP logon attempt and the `related.ip.keyword` field that represents the IP of the computer initiating the succsessful RDP logon attempt. This will allow us to display the involved machines alongside the count of successful logon attempts, as shown in the image.

![Rows configuration: Select host.hostname.keyword, top 1000 values, ranked by number of logins in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization40.png)

![Rows configuration: Select related.ip.keyword, top 1000 values, ranked by number of logins in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization41.png)

As discussed, we want to monitor successful RDP logons specifically related to service accounts, knowing for a fact that all service accounts of the environment start with `svc-`. So, to conclude our visualization we need to specify the following KQL query.

        shellsession
`user.name: svc-*`

**Note**: As you can see we don't use the `.keyword` field in KQL queries.

---

In Kibana Query Language (KQL) and Elasticsearch, we avoid using the `.keyword` field for this specific wildcard search primarily because of **case sensitivity and exact-match constraints.**

Here is the technical breakdown of why `.keyword` is avoided here:

**1. Keyword Fields are Unanalyzed (Strict Case Sensitivity)**
When a field is stored as a `.keyword` (e.g., `user.name.keyword`), Elasticsearch stores the exact, literal string exactly as the log generated it, preserving all uppercase letters, spaces, and punctuation.

* If you query `user.name.keyword: svc-*`, KQL performs a **strictly case-sensitive** prefix search.
* It will match `svc-sql` but it will completely **miss** `SVC-sql`, `Svc-Admin`, or `DOMAIN\svc-web`.

**2. Standard Fields are Analyzed (Forgiving and Case-Insensitive)**
When you query the base `user.name` field without `.keyword`, you are querying the **text** version of the field. Standard text fields pass through an analyzer during ingestion that typically lowercases all characters and breaks strings apart at punctuation (like hyphens and slashes).

* Querying `user.name: svc-*` takes advantage of this normalization.
* It becomes **case-insensitive**, meaning it will successfully catch `SVC-Admin`, `svc-admin`, and `Svc-Admin` equally.

**The SOC Analyst Takeaway:**
In security monitoring, you cannot rely on humans, attackers, or disparate IT systems to be perfectly consistent with capitalization. Using `.keyword` with a wildcard creates a dangerous blind spot where a log like `SVC-Backup` could slip past your dashboard.

*Rule of thumb:* Use **`.keyword`** when you need to run aggregations, sort data, or filter by a 100% exact, known string. Use the base **`text`** field when using wildcards or free-text searches to ensure you don't miss variations.

![Elastic dashboard showing user logins: svc-sql1 connected to PKI, 2 logins.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization43.png)

Now we can see four columns in the table, which contain the following information:

1.  The service account whose credentials generated the successful RDP logon attempt event.
2.  The machine on which the logon attempt occurred.
3.  The IP of the machine that initiated the logon attempt.
4.  The number of times the event has occurred (based on the specified time frame or the entire data set, depending on the settings).

Finally, click on "Save and return", and you will observe that the new visualization is added to the dashboard.

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.

---

# ==🟡SIEM Visualization Example 4: Users Added Or Removed From A Local Group (Within A Specific Timeframe)==

In this SIEM visualization example, we aim to create a visualization to monitor user additions or removals from the local "Administrators" group from March 5th 2023 to date.

Our visualization will be based on the following Windows event logs.

-   [4732: A member was added to a security-enabled local group](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4732)
-   [4733: A member was removed from a security-enabled local group](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4733)

Navigate to the bottom of this section and click on `Click here to spawn the target system!`.

Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard".

A prebaked dashboard should be visible. Let's click on the "pencil"/edit icon.

![Elastic dashboard with SOC-Alerts listed, option to create or edit dashboards.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization16.png)

Now, to initiate the creation of our first visualization, we simply have to click on the "Create visualization" button.

Upon initiating the creation of our first visualization, the following new window will appear with various options and settings.

![Elastic dashboard: Add filter, select windows index, bar vertical stacked chart.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization1.png)

There are four things for us to notice on this window:

1.  A filter option that allows us to filter the data before creating a graph. In this case our goal is to display user additions or removals from the local "Administrators" group. We can use a filter to only consider event IDs that match `4732 – A member was added to a security-enabled local group` and `4733 – A member was removed from a security-enabled local group`. We can also use a filter to only consider 4732 and 4733 events where the local group is the "Administrators" one.  
    ![Elastic dashboard filter: event.code is 4732 or 4733, group.name is administrators.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization44.png)
2.  This field indicates the data set (index) that we are going to use. It is common for data from various infrastructure sources to be separated into different indices, such as network, Windows, Linux, etc. In this particular example, we will specify `windows*` in the "Index pattern".
3.  This search bar provides us with the ability to double-check the existence of a specific field within our data set, serving as another way to ensure that we are looking at the correct data. We are interested in the `user.name.keyword` field. We can use the search bar to quickly perform a search and verify if this field is present and discovered within our selected data set. This allows us to confirm that we are accessing the desired field and working with accurate data.  
    ![Elastic dashboard: Filter event.code 4625, search user fields.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization11.png)
4.  Lastly, this drop-down menu enables us to select the type of visualization we want to create. The default option displayed in the earlier image is "Bar vertical stacked". If we click on that button, it will reveal additional available options (image redacted as not all options fit on the screen). From this expanded list, we can choose the desired visualization type that best suits our requirements and data presentation needs.  
    ![Visualization type menu: Bar vertical stacked selected.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization4.png)

* * *

For this visualization, let's select the "Table" option. After selecting the "Table", we can proceed to click on the "Rows" option. This will allow us to choose the specific data elements that we want to include in the table view.

![Table configuration: Add fields to Rows, Columns, and Metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization5.png)

Let's configure the "Rows" settings as follows.

![Rows configuration: Select user.name.keyword, top 1000 values, ranked by count of records in descending order.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization6.png)

Moving forward, let's close the "Rows" window and proceed to enter the "Metrics" configuration.

![Table configuration: Rows set to top values of user.name.keyword, add fields to Columns and Metrics.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization7.png)

In the "Metrics" window, let's select "count" as the desired metric.

![Metrics selection: Choose 'Count' function.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization8.png)

One final addition to the table is to include some more "Rows" settings to enhance our understanding.

-   Which user was added to or removed from the group? (`winlog.event_data.MemberSid.keyword` field)
-   To which group was the addition or the removal performed? (double-checking that it is the "Administrators" one) (`group.name.keyword` field)
-   Was the user added to or removed from the group? (`event.action.keyword` field)
-   On which machine did the action occur? (`host.name.keyword` field)  
    ![Table showing top values of user.name, winlog.event_data.MemberSid, group.name, event.action, host.name, with record counts.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization46.png)

Click on "Save and return", and you will observe that the new visualization is added to the dashboard.

As discussed, we want to monitor user additions or removals from the local "Administrators" group _within a specific timeframe (March 5th 2023 to date)_.

We can narrow the scope of our visualization as follows.

![Dashboard showing failed logon attempts and RDP logon for service account, with options to edit lens and create drilldown.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization47.png)

![Dashboard showing failed logon attempts and RDP logon for service account, with options to customize time range.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization48.png)

![Dashboard with failed logon attempts and RDP logon, showing panel time range customization to March 5, 2023.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/211/visualization50.png)

Finally, let's click on the "Save" button so that all our edits persist.

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.

`Note`: As Elasticsearch uses `buckets` to aggregate data (time ranges, etc.) into groups, we must use an `absolute` time range on every occasion when creating the visualization. If we don't consider this, the bucket will showcase a weekly interval instead of a daily one. For example, an absolute time range can be January 1st to January 31st, 2023.

---

# The Triaging Process

Source: https://academy.hackthebox.com/app/module/211/section/2286

# The Triaging Process

* * *

## What Is Alert Triaging?

`Alert triaging`, performed by a Security Operations Center (SOC) analyst, is the process of evaluating and prioritizing security alerts generated by various monitoring and detection systems to determine their level of threat and potential impact on an organization's systems and data. It involves systematically reviewing and categorizing alerts to effectively allocate resources and respond to security incidents.

`Escalation` is an important aspect of alert triaging in a SOC environment. The escalation process typically involves notifying supervisors, incident response teams, or designated individuals within the organization who have the authority to make decisions and coordinate the response effort. The SOC analyst provides detailed information about the alert, including its severity, potential impact, and any relevant findings from the initial investigation. This allows the decision-makers to assess the situation and determine the appropriate course of action, such as involving specialized teams, initiating broader incident response procedures, or engaging external resources if necessary.

Escalation ensures that critical alerts receive prompt attention and facilitates effective coordination among different stakeholders, enabling a timely and efficient response to potential security incidents. It helps to leverage the expertise and decision-making capabilities of individuals who are responsible for managing and mitigating higher-level threats or incidents within the organization.

* * *

## What Is The Ideal Triaging Process?

1.  `Initial Alert Review`:

-   Thoroughly review the initial alert, including metadata, timestamp, source IP, destination IP, affected systems, and triggering rule/signature.
-   Analyze associated logs (network traffic, system, application) to understand the alert's context.

2.  `Alert Classification`:

-   Classify the alert based on severity, impact, and urgency using the organization's predefined classification system.

3.  `Alert Correlation`:

-   Cross-reference the alert with related alerts, events, or incidents to identify patterns, similarities, or potential indicators of compromise (IOCs).
-   Query the SIEM or log management system to gather relevant log data.
-   Leverage threat intelligence feeds to check for known attack patterns or malware signatures.

4.  `Enrichment of Alert Data`:

-   Gather additional information to enrich the alert data and gain context:
    -   Collect network packet captures, memory dumps, or file samples associated with the alert.
    -   Utilize external threat intelligence sources, open-source tools, or sandboxes to analyze suspicious files, URLs, or IP addresses.
    -   Conduct reconnaissance of affected systems for anomalies (network connections, processes, file modifications).

5.  `Risk Assessment`:

-   Evaluate the potential risk and impact to critical assets, data, or infrastructure:
    -   Consider the value of affected systems, sensitivity of data, compliance requirements, and regulatory implications.
    -   Determine likelihood of a successful attack or potential lateral movement.

6.  `Contextual Analysis`:

-   The analyst considers the context surrounding the alert, including the affected assets, their criticality, and the sensitivity of the data they handle.
-   They evaluate the security controls in place, such as firewalls, intrusion detection/prevention systems, and endpoint protection solutions, to determine if the alert indicates a potential control failure or evasion technique.
-   The analyst assesses the relevant compliance requirements, industry regulations, and contractual obligations to understand the implications of the alert on the organization's legal and regulatory compliance posture.

7.  `Incident Response Planning`:

-   Initiate an incident response plan if the alert is significant:
    -   Document alert details, affected systems, observed behaviors, potential IOCs, and enrichment data.
    -   Assign incident response team members with defined roles and responsibilities.
    -   Coordinate with other teams (network operations, system administrators, vendors) as necessary.

8.  `Consultation with IT Operations`:

-   Assess the need for additional context or missing information by consulting with IT operations or relevant departments:
    -   Engage in discussions or meetings to gather insights on the affected systems, recent changes, or ongoing maintenance activities.
    -   Collaborate to understand any known issues, misconfigurations, or network changes that could potentially generate false-positive alerts.
    -   Gain a holistic understanding of the environment and any non-malicious activities that might have triggered the alert.
    -   Document the insights and information obtained during the consultation.

9.  `Response Execution`:

-   Based on the alert review, risk assessment, and consultation, determine the appropriate response actions.
-   If the additional context resolves the alert or identifies it as a non-malicious event, take necessary actions without escalation.
-   If the alert still indicates potential security concerns or requires further investigation, proceed with the incident response actions.

10.  `Escalation`:

-   Identify triggers for escalation based on organization's policies and alert severity:
    -   Triggers may include compromise of critical systems/assets, ongoing attacks, unfamiliar/sophisticated techniques, widespread impact, or insider threats.
-   Assess the alert against escalation triggers, considering potential consequences if not escalated.
-   Follow internal escalation process, notifying higher-level teams/management responsible for incident response.
-   Provide comprehensive alert summary, severity, potential impact, enrichment data, and risk assessment.
-   Document all communication related to escalation.
-   In some cases, escalate to external entities (law enforcement, incident response providers, CERTs) based on legal/regulatory requirements.

11.  `Continuous Monitoring`:

-   Continuously monitor the situation and incident response progress.
-   Maintain open communication with escalated teams, providing updates on developments, findings, or changes in severity/impact.
-   Collaborate closely with escalated teams for a coordinated response.

12.  `De-escalation`:

-   Evaluate the need for de-escalation as the incident response progresses and the situation is under control.
-   De-escalate when the risk is mitigated, incident is contained, and further escalation is unnecessary.
-   Notify relevant parties, providing a summary of actions taken, outcomes, and lessons learned.

Regularly review and update the process, aligning it with organizational policies, procedures, and guidelines. Adapt the process to address emerging threats and evolving needs.

---

# The Triaging Process

Source: https://academy.hackthebox.com/app/module/211/section/2256

# The Triaging Process

* * *

## What Is Alert Triaging?

`Alert triaging`, performed by a Security Operations Center (SOC) analyst, is the process of evaluating and prioritizing security alerts generated by various monitoring and detection systems to determine their level of threat and potential impact on an organization's systems and data. It involves systematically reviewing and categorizing alerts to effectively allocate resources and respond to security incidents.

`Escalation` is an important aspect of alert triaging in a SOC environment. The escalation process typically involves notifying supervisors, incident response teams, or designated individuals within the organization who have the authority to make decisions and coordinate the response effort. The SOC analyst provides detailed information about the alert, including its severity, potential impact, and any relevant findings from the initial investigation. This allows the decision-makers to assess the situation and determine the appropriate course of action, such as involving specialized teams, initiating broader incident response procedures, or engaging external resources if necessary.

Escalation ensures that critical alerts receive prompt attention and facilitates effective coordination among different stakeholders, enabling a timely and efficient response to potential security incidents. It helps to leverage the expertise and decision-making capabilities of individuals who are responsible for managing and mitigating higher-level threats or incidents within the organization.

* * *

## What Is The Ideal Triaging Process?

1.  `Initial Alert Review`:

-   Thoroughly review the initial alert, including metadata, timestamp, source IP, destination IP, affected systems, and triggering rule/signature.
-   Analyze associated logs (network traffic, system, application) to understand the alert's context.

2.  `Alert Classification`:

-   Classify the alert based on severity, impact, and urgency using the organization's predefined classification system.

3.  `Alert Correlation`:

-   Cross-reference the alert with related alerts, events, or incidents to identify patterns, similarities, or potential indicators of compromise (IOCs).
-   Query the SIEM or log management system to gather relevant log data.
-   Leverage threat intelligence feeds to check for known attack patterns or malware signatures.

4.  `Enrichment of Alert Data`:

-   Gather additional information to enrich the alert data and gain context:
    -   Collect network packet captures, memory dumps, or file samples associated with the alert.
    -   Utilize external threat intelligence sources, open-source tools, or sandboxes to analyze suspicious files, URLs, or IP addresses.
    -   Conduct reconnaissance of affected systems for anomalies (network connections, processes, file modifications).

5.  `Risk Assessment`:

-   Evaluate the potential risk and impact to critical assets, data, or infrastructure:
    -   Consider the value of affected systems, sensitivity of data, compliance requirements, and regulatory implications.
    -   Determine likelihood of a successful attack or potential lateral movement.

6.  `Contextual Analysis`:

-   The analyst considers the context surrounding the alert, including the affected assets, their criticality, and the sensitivity of the data they handle.
-   They evaluate the security controls in place, such as firewalls, intrusion detection/prevention systems, and endpoint protection solutions, to determine if the alert indicates a potential control failure or evasion technique.
-   The analyst assesses the relevant compliance requirements, industry regulations, and contractual obligations to understand the implications of the alert on the organization's legal and regulatory compliance posture.

7.  `Incident Response Planning`:

-   Initiate an incident response plan if the alert is significant:
    -   Document alert details, affected systems, observed behaviors, potential IOCs, and enrichment data.
    -   Assign incident response team members with defined roles and responsibilities.
    -   Coordinate with other teams (network operations, system administrators, vendors) as necessary.

8.  `Consultation with IT Operations`:

-   Assess the need for additional context or missing information by consulting with IT operations or relevant departments:
    -   Engage in discussions or meetings to gather insights on the affected systems, recent changes, or ongoing maintenance activities.
    -   Collaborate to understand any known issues, misconfigurations, or network changes that could potentially generate false-positive alerts.
    -   Gain a holistic understanding of the environment and any non-malicious activities that might have triggered the alert.
    -   Document the insights and information obtained during the consultation.

9.  `Response Execution`:

-   Based on the alert review, risk assessment, and consultation, determine the appropriate response actions.
-   If the additional context resolves the alert or identifies it as a non-malicious event, take necessary actions without escalation.
-   If the alert still indicates potential security concerns or requires further investigation, proceed with the incident response actions.

10.  `Escalation`:

-   Identify triggers for escalation based on organization's policies and alert severity:
    -   Triggers may include compromise of critical systems/assets, ongoing attacks, unfamiliar/sophisticated techniques, widespread impact, or insider threats.
-   Assess the alert against escalation triggers, considering potential consequences if not escalated.
-   Follow internal escalation process, notifying higher-level teams/management responsible for incident response.
-   Provide comprehensive alert summary, severity, potential impact, enrichment data, and risk assessment.
-   Document all communication related to escalation.
-   In some cases, escalate to external entities (law enforcement, incident response providers, CERTs) based on legal/regulatory requirements.

11.  `Continuous Monitoring`:

-   Continuously monitor the situation and incident response progress.
-   Maintain open communication with escalated teams, providing updates on developments, findings, or changes in severity/impact.
-   Collaborate closely with escalated teams for a coordinated response.

12.  `De-escalation`:

-   Evaluate the need for de-escalation as the incident response progresses and the situation is under control.
-   De-escalate when the risk is mitigated, incident is contained, and further escalation is unnecessary.
-   Notify relevant parties, providing a summary of actions taken, outcomes, and lessons learned.

Regularly review and update the process, aligning it with organizational policies, procedures, and guidelines. Adapt the process to address emerging threats and evolving needs.

---

# Skills Assessment

Source: https://academy.hackthebox.com/app/module/211/section/2256

# Skills Assessment

* * *

## Dashboard Review & Critical Thinking Exercise

Congratulations,

You have been hired in Eagle as a SOC Tier 1 analyst. Yesterday was your on-boarding day with the company, and today you will be familiarized with the SOC. Your day will begin by meeting up with a senior analyst, who will provide insights into the environment, and afterwards, you are expected to begin monitoring alerts and security events in our home-cooked SOC dashboards.

The following are your notes after meeting the senior analyst, who provided insights into the environment:

-   The organization has moved all hosting to the cloud; the old DMZ network is closed down, so no more servers exist there.
-   The IT operation team (the core IT admins) consists of four people. They are the only ones with high privileges in the environment.
-   The IT operation team often tends to use the default administrator account(s) even if they are told otherwise.
-   All endpoint devices are hardened according to CIS hardening baselines. Whitelisting exists to a limited extent.
-   IT security has created a privileged admin workstation (PAW) and requires that all admin activities be performed on this machine.
-   The Linux environment is primarily 'left over' servers from back in the day, which have very little, if any, activity on a regular day. The root user account is not used; due to audit findings, the account was blocked from connecting remotely, and users who require those rights will need to escalate via the sudo command.
-   Naming conventions exist and are strictly followed; for example, service accounts contain '-svc' as part of their name. Service accounts are created with long, complex passwords, and they perform a very specific task (most likely running services locally on machines).

* * *

If you had a running instance of the target please reset it by clicking on the "Reset Target" icon. This will ensure that you regain access to the preconfigured dashboard, that you may have deleted during the SIEM visualization-related sections.

Now you are free to take your seat and start monitoring. Navigate to `http://[Target IP]:5601`, click on the side navigation toggle, and click on "Dashboard". Review the `SOC-Alerts` dashboard.

-   `Visualization 1: Failed logon attempts (All users)`  
    Such a visualization might reveal potential brute force attacks. It's important to identify any single user with numerous failed attempts or perhaps, various users connecting to (or from) the same endpoint device. However, the current data does not point towards any such scenario. One anomaly is noticeable though. **Hint**: It is related to the "sql-svc1" account.
-   `Visualization 2: Failed logon attempts (Disabled user)`  
    It seems that there is one incident where the user "Anni" has tried to authenticate, despite the account being disabled.
-   `Visualization 3: Failed logon attempts (Admin users only)`  
    **Hint**: Check if all events took place on either Privileged Access Workstations (PAWs) or Domain Controllers.
-   `Visualization 4: RDP logon for service account`  
    Service accounts in this environment serve a very specialized function. Do you notice anything that warrants suspicion?
-   `Visualization 5: User added or removed from a local group`  
    An administrator has incorporated an individual (who is only represented by the SID value) into the "Administrators" group. Should you escalate to a Tier 2/3 analyst or consult with the IT Operations department first?
-   `Visualization 6: Admin logon not from PAW`  
    Administrators should exclusively utilize PAWs for server remote connections. Should you escalate to a Tier 2/3 analyst or consult with the IT Operations department first?
-   `Visualization 7: SSH Logins`  
    Be reminded that the root user account is not typically in use.

Go through the questions below and enter your answers.

Please allow 3-5 minutes for Kibana to become available after spawning the target of the questions below.

[^1]: In Kibana Query Language (KQL) and Elasticsearch, we avoid using the `.keyword` field for this specific wildcard search primarily because of **case sensitivity and exact-match constraints.**
	
	Here is the technical breakdown of why `.keyword` is avoided here:
	
	**1. Keyword Fields are Unanalyzed (Strict Case Sensitivity)**
	When a field is stored as a `.keyword` (e.g., `user.name.keyword`), Elasticsearch stores the exact, literal string exactly as the log generated it, preserving all uppercase letters, spaces, and punctuation.
	
	* If you query `user.name.keyword: svc-*`, KQL performs a **strictly case-sensitive** prefix search.
	* It will match `svc-sql` but it will completely **miss** `SVC-sql`, `Svc-Admin`, or `DOMAIN\svc-web`.
	
	**2. Standard Fields are Analyzed (Forgiving and Case-Insensitive)**
	When you query the base `user.name` field without `.keyword`, you are querying the **text** version of the field. Standard text fields pass through an analyzer during ingestion that typically lowercases all characters and breaks strings apart at punctuation (like hyphens and slashes).
	
	* Querying `user.name: svc-*` takes advantage of this normalization.
	* It becomes **case-insensitive**, meaning it will successfully catch `SVC-Admin`, `svc-admin`, and `Svc-Admin` equally.
	
	**The SOC Analyst Takeaway:**
	In security monitoring, you cannot rely on humans, attackers, or disparate IT systems to be perfectly consistent with capitalization. Using `.keyword` with a wildcard creates a dangerous blind spot where a log like `SVC-Backup` could slip past your dashboard.
	
	*Rule of thumb:* Use **`.keyword`** when you need to run aggregations, sort data, or filter by a 100% exact, known string. Use the base **`text`** field when using wildcards or free-text searches to ensure you don't miss variations.
