"""skjold framework integrations.

This subpackage ships the callback/adapter classes that let popular agent
frameworks log every step to the skjold audit chain.

Available integrations (importable lazily — each requires its framework as
an opt-in extra):

- ``attestix.integrations.langchain`` — ``skjoldCallback`` (LangChain
  ``BaseCallbackHandler``). Install: ``pip install 'skjold[langchain]'``.
- ``attestix.integrations.openai_agents`` — ``skjoldAuditHook`` (helper for
  the OpenAI Agents SDK). Install: ``pip install 'skjold[openai-agents]'``.
- ``attestix.integrations.crewai`` — ``skjoldCrewAdapter`` (helper for
  CrewAI). Install: ``pip install 'skjold[crewai]'``.

The integration modules import their respective framework lazily so that
``import attestix.integrations`` alone never requires the framework to be
installed.
"""

__all__ = ["langchain", "openai_agents", "crewai"]
