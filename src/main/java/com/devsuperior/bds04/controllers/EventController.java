package com.devsuperior.bds04.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.devsuperior.bds04.dto.EventDTO;
import com.devsuperior.bds04.services.EventService;

@RestController
@RequestMapping(value = "/events")
public class EventController {

	@Autowired
	private EventService eventService;

	@GetMapping
	public ResponseEntity<Page<EventDTO>> findAllPaged(Pageable pageable) {
		Page<EventDTO> list = eventService.findAllPaged(pageable);
		return ResponseEntity.ok().body(list);
	}

}
